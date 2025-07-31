from dataclasses import asdict, dataclass, field
from enum import auto
from functools import lru_cache
from itertools import product
from pathlib import Path
from typing import Optional, Union

import cdk8s
import pandas as pd
from loguru import logger
from strenum import LowercaseStrEnum, SnakeCaseStrEnum, StrEnum

from kalm_benchmark.evaluation.scanner_manager import SCANNERS
from kalm_benchmark.evaluation.utils import get_version_from_result_file
from kalm_benchmark.io import get_scanner_result_file_paths
from kalm_benchmark.manifest_generator.check import Check
from kalm_benchmark.manifest_generator.constants import (
    MISSING_CHECKS,
    CheckKey,
    CheckStatus,
)
from kalm_benchmark.manifest_generator.gen_manifests import generate_manifests

from .scanner.scanner_evaluator import CheckCategory, CheckResult, ScannerBase


class Metric(StrEnum):
    Accuracy = "Accuracy"
    F1 = "F1-Score"


class ResultType(StrEnum):
    Covered = auto()  # the normal case where both an expected and an actual result are available
    Missing = auto()  # the scanner did not provide a result
    Extra = auto()  # the scanner reported something without a corresponding check


class Col(SnakeCaseStrEnum):
    Category = auto()
    CheckId = auto()
    CheckedPath = auto()
    Description = auto()
    Details = auto()
    Expected = auto()
    Got = auto()
    MatchedPath = auto()
    Name = auto()
    PathToCheck = auto()
    ScannerCheckId = auto()
    ScannerCheckName = auto()
    ResultType = auto()


@dataclass
class ScannerInfo:
    # note: the order of the fields dictates the initial order of the columns in the UI
    name: str
    image: Optional[str] = None
    version: Optional[str] = None
    score: float = 0.0
    coverage: float = 0.0
    cat_admission_ctrl: str = "0/0"
    cat_data_security: str = "0/0"
    cat_IAM: str = "0/0"
    cat_network: str = "0/0"
    cat_reliability: str = "0/0"
    cat_segregation: str = "0/0"
    cat_vulnerability: str = "0/0"
    cat_workload: str = "0/0"
    cat_misc: str = "0/0"
    can_scan_manifests: bool = False
    can_scan_cluster: bool = False
    ci_mode: bool = False
    runs_offline: bool | str = False
    custom_checks: str = False
    formats: list[str] = field(default_factory=list)
    is_valid_summary: bool = True


def get_confusion_matrix(df: pd.DataFrame, margins: bool = True) -> pd.DataFrame:
    """
    Generate a confusion matrix between the expected and the actual result of a particular check.
    Observations where either the actual or the expected outcome is missing will be not taken into account.
    :param df: the dataframe containing the execution results
    :param margins: if the flag is set then margin row and columns with the total sums is added as well
    :returns: the confusion matrix of the execution results
    """
    # treat results without a status as having passed, as the tool did not handle it
    got = df.got.replace("-", CheckStatus.Pass)
    actual = df.expected.replace("-", CheckStatus.Pass)
    margins_name = "Total"
    df_xtab = pd.crosstab(actual, got, margins=margins, margins_name=margins_name)
    # ensure that all rows/columns are present in the resulting dataframe, even if there are no actual values
    # df = df.reindex(index=["alert", "pass"], columns=["alert", "pass"], fill_value=0)
    labels = [CheckStatus.Alert, CheckStatus.Pass]
    if margins:
        labels.append(margins_name)

    df_xtab = df_xtab.reindex(
        index=labels,
        columns=labels,
        # columns={"alert": "expected alert", "pass": "expected pass"},
        fill_value=0,
    )
    df_xtab = df_xtab.rename(
        index={CheckStatus.Alert: "actual alert", CheckStatus.Pass: "actual pass"},
        columns={CheckStatus.Alert: "scanner alert", CheckStatus.Pass: "scanner pass"},
    )

    return df_xtab


def calculate_score(df: pd.DataFrame, metric: Metric = Metric.F1) -> float:
    """
    Calculate a score from the confusion matrix of the expected and actual check results.
    This calculation excludes missing check results or expected checks and focuses only
    on cases where both the expected and actual values are known.
    :param df: the dataframe from which the confusion matrix will be determined
    :param metric: the type of metric used as the score.
    Currently, F1-score (default) and accuracy are supported.
    The F1 is used as the default, because the confusion matrix is expected to be imbalanced
    and false classifications are of interest.
    :returns: the score as a single numeric value
    """
    df_xtab = get_confusion_matrix(df)
    # columns are the expected values, rows are the actual values
    tp, fp, expect_alerts = df_xtab["scanner alert"].values
    fn, tn, expect_passes = df_xtab["scanner pass"].values

    if metric == Metric.F1:
        if tp == 0:  # if there are no true positives the F1 can't be calculated
            logger.warning("Could not calculate F1-score because there are not true positives in the data")
            # return the the worst possible value
            return 0.0

        precision = tp / (tp + fp)
        recall = tp / (tp + fn)
        return 2 * (precision * recall) / (precision + recall)
    elif metric == Metric.Accuracy:
        return (tp + tn) / (expect_alerts + expect_passes)


def classify_result(row: pd.Series) -> ResultType:
    """
    Classify if a result (represented as pandas series) is a "covered", "missing" or "extra" check.
    :param row: a check result represented as a row (i.e. a pandas Series)
    :returns: the type of result
    """
    if row["got"] == "-":
        return ResultType.Missing
    elif row["expected"] == "-":
        return ResultType.Extra
    else:
        return ResultType.Covered


def classify_results(df: pd.DataFrame) -> pd.DataFrame:
    """
    Classify every result in a dataframe with the execution results into one of the ResultType
    :param df: the dataframe containing the execution results
    :returns: the same dataframe with the additional column "result_type"
    """
    df["result_type"] = df.apply(classify_result, axis=1)
    return df


def calculate_coverage(df: pd.DataFrame) -> float:
    """
    Calculate the coverage of the checks implemented by a scanner against the benchmark manifests.
    :param df: the dataframe containing the results of the execution.
    :returns: the coverage as a single numerical value
    """
    num_coverage = len(df[df["result_type"] == ResultType.Covered])
    num_total = len(df)
    return num_coverage / num_total


def load_scanner_results_from_file(
    scanner: ScannerBase, path: Path | None = None, format: str = "json"
) -> list[CheckResult]:
    """Load the stored scan results from the specified file

    :param scanner: in instance of the scanner for which the results will be loaded
    :param path: optional path to the check results of the scanner. If no path is provided, then
    it defaults to the name of scanner in the data directory with the specified format as file extension.
    :param format: the format of the loaded result file, by default it's "json"
    :return: the collection of scan results stored in the file
    """
    if path is None:
        # TODO properly implement the retrieval of the correct result file
        # files = get_result_files_of_scanner(scanner.NAME)
        path = Path(f"./data/{scanner.NAME.lower()}.{format}")
    return scanner.load_results(path)


def evaluate_scanner(
    scanner: ScannerBase,
    results: list[CheckResult],
    keep_redundant_checks: bool = False,
):
    """
    Loads the results of the specified scanner from the `data` folder. It's expected, that the scanner results
    is named after the scanner itself. Optionally a file format can be specified.
    :param scanner: the name of the scanner and consequently the name of the result file
    :param results: the collection of scan results of the scanner
    :param keep_redundant_checks: if false then all checks that pass, yet have no 'expected' status will be removed
    :return: the evaluated results as a pandas dataframe
    """
    if len(results) == 0:
        return None
    df_scanner = pd.DataFrame(results)

    # use the check id derived from the object name as fallback if none could be extracted from scanner
    check_id_pattern = r"^(\w+(?:-\d+)+)"  # match the first letters and then the numbers following it
    extracted_check_id = df_scanner["obj_name"].str.extract(check_id_pattern, expand=False)
    df_scanner["check_id"] = df_scanner["check_id"].fillna(extracted_check_id).str.upper()

    # use outer join to ensure coverage can be properly analysed
    df_bench = load_benchmark()
    df = merge_dataframes(df_bench, df_scanner, id_column=Col.CheckId, path_columns=[Col.PathToCheck, Col.CheckedPath])

    if not keep_redundant_checks:
        df = _filter_redundant_extra_checks(df)

    df = (
        df.pipe(_add_comparison_cols)  # temporary columns for analysing parsing results
        .pipe(_coalesce_columns, primary_col="obj_name", secondary_col="name", result_name="name")
        .pipe(drop_duplicates)
        # note: use dataframe provided via lambda as "outer" df is not updated along the pipeline
        .assign(category=lambda _df: _df.apply(categorize_result, args=(scanner,), axis=1))
        .pipe(filter_out_of_scope_alerts)
        .fillna("-")
        .pipe(classify_results)
        .pipe(order_columns)
    )
    return df


def merge_dataframes(
    df1: pd.DataFrame,
    df2: pd.DataFrame,
    id_column: str | tuple[str, str],
    path_columns: Optional[str | tuple[str, str]] = None,
    keep_matched_paths: bool = False,
) -> pd.DataFrame:
    """Merge two dataframe on one or two columns.
    If two columns are provided, then the column is expected to contain
    a path or several potential paths of the checked field. In the case of multiple path alternatives,
    only one has to match the path in the other dataframe.

    :param df1: the first dataframe
    :param df2: the second dataframe
    :param id_column: one column as string or multiple columns as a list of strings
    :param path_columns: either the name of the path column in both dataframes or
        a tuple of two strings with the name of the path column in the respective dataframe.
        If the name is the same in both dataframes, the column after the merge will contain only the matched paths.
    :param keep_matched_paths: flag whether to add a column with the path(s) which matched
    :return: the dataframe resulting from the merge of the provided two dataframes.
    """
    # 1) first merge on just the check id
    suffixes = ("", "_2")
    if isinstance(id_column, str):
        df = df1.merge(df2, on=id_column, how="outer", suffixes=suffixes)
    else:
        df = df1.merge(df2, left_on=id_column[0], right_on=id_column[1], how="outer", suffixes=suffixes)

    # then check if paths match - if they are also part of the merge criterion
    if path_columns is not None:
        is_same_path_col = isinstance(path_columns, str)
        # if it's a string, then the columns have the same name in both dataframes and will have resulted in
        # a collision during previous merge -> reflect this change of the column names here
        _path_cols = [f"{path_columns}{sfx}" for sfx in suffixes] if is_same_path_col else path_columns
        matched_paths = df.apply(_compare_paths, args=(_path_cols,), axis=1)

        if is_same_path_col:
            df[path_columns] = matched_paths
        elif keep_matched_paths:
            df[Col.MatchedPath] = matched_paths

        # adjust results if paths don't match: split left and right part into separate rows
        # but only those who have no combination if id and paths col in the dataframe (i.e. no data loss)
        df_no_matches = df[matched_paths == ""]
        # correct the results by dropping the results without a path match.
        df = df.drop(df_no_matches.index)

        # Then reproduce the 'outer' join by merging the individual dataframes back in,
        # but only for the cases where there was no match
        suffixes = ("_x", "_y")
        excluded_cols = [Col.Expected, Col.Got] + [path_columns] if is_same_path_col else path_columns
        for outer_df in [df1, df2]:
            other_cols = [c for c in outer_df.columns if c not in excluded_cols]
            conflicting_cols = [c for c in df.columns if c in outer_df.columns and c not in other_cols]
            df = df.merge(outer_df, how="outer", on=other_cols, suffixes=suffixes)
            # any column with a suffix is the result of name collision
            for col in conflicting_cols:
                # the first dataframe in merge is considered to be the primary one, this is replected in suffix order
                c1, c2 = [f"{col}{s}" for s in suffixes]
                # coalesce into original column
                df = _coalesce_columns(df, c1, c2, result_name=col)

    return df


def _filter_redundant_extra_checks(df: pd.DataFrame) -> pd.DataFrame:
    """Remove redundant check results from the dataframe.
    A check is redundant if the benchmark has no expected result and
    the result from the scanner is either a 'pass' or also missing.

    :param df: the dataframe whose rows will be filtered
    :return: the dataframe without any redundant check results
    """
    no_expectation = df[Col.Expected].isnull()
    no_scanner_alert = (df[Col.Got] == CheckStatus.Pass) | df[Col.Got].isnull()

    return df[~(no_expectation & no_scanner_alert)]


def _compare_paths(row: pd.Series, paths_cols: list[str]) -> str:
    paths1, paths2 = row.fillna("")[paths_cols]

    # special case if neither specifies a path then it's also a match
    # use "-" to indicate that to avoid being filtered later on
    if paths1 == "" and paths2 == "":
        return "-"

    paths1 = set(paths1.split("|"))
    paths2 = set(paths2.split("|"))

    # the the second path can be more specific than first path to count as a match
    match = [p2 for p1, p2 in product(paths1, paths2) if _is_partial_match(p1, p2)]
    return "|".join(sorted(match))


def _is_partial_match(reference_path: str, checked_path: str) -> bool:
    """Check if a path, which consists of multiple parts separated by a '.' is
    a partial match to the other provided path.

    :param reference_path: the path to which the checked path is compared
    :param checked_path: the path, which is checked for the patial match to the other path
    :return: bool if it the 2nd path is a partial match of the first path
    """
    ref_tokens = reference_path.lower().split(".")
    checked_tokens = checked_path.lower().split(".")
    # pad the checked_tokens if it's shorter than the ref_tokens, so the later `zip` won't truncated it
    len_diff = len(ref_tokens) - len(checked_tokens)
    if len_diff > 0:
        checked_tokens += len_diff * [""]

    return all(r == z for r, z in zip(ref_tokens, checked_tokens))


def _add_comparison_cols(df: pd.DataFrame) -> pd.DataFrame:
    # the 2 "compare" columns columns are temporary analysis instruments and are bound to be removed
    return df.assign(compare_name=df["obj_name"] == df["name"], compare_expected=df["expected"] == df["expected_2"])


def filter_out_of_scope_alerts(df: pd.DataFrame) -> pd.DataFrame:
    """Ignore alerts for Kubernetes objects in special namespace as these are out of scope.
    The only exception is if the alert category is about the infrastructure security.

    :param df: the dataframe which will be filtered
    :return: a filtered copy of the dataframe
    """
    for col in ["namespace", "category", "name"]:
        if col not in df.columns:
            logger.error(f"The column '{col}' is required to filter out of scope alerts. No filter was applied!")
            return df

    # kube-system and kube-public are actually used for 2 checks, so keep them in the results
    special_namespaces = ["kube-node-lease", "local-path-storage"]
    # special_namespaces = ["kube-system", "kube-public", "kube-node-lease", "local-path-storage"]
    # all namespaces and its objects except for the special ones are in the scope of the benchmark
    managing_ns_in_scope = ~df["namespace"].isin(special_namespaces)
    is_infra_check = df["category"] == CheckCategory.Infrastructure
    is_not_special_ns = ~(df["name"].isin(special_namespaces))
    return df[managing_ns_in_scope & is_not_special_ns | is_infra_check]


def _coalesce_columns(
    df: pd.DataFrame,
    primary_col: str,
    secondary_col: str,
    result_name: Optional[str] = None,
) -> pd.DataFrame:
    def _pick_value(row: pd.Series, primary: str, secondary: str) -> str:
        if row[primary] and not pd.isnull(row[primary]):
            return row[primary]
        return row[secondary]

    df_res = df.copy()

    res_col = df.apply(_pick_value, args=(primary_col, secondary_col), axis=1)
    drop_cols = [secondary_col]
    if result_name is not None and result_name != primary_col:
        drop_cols.append(primary_col)
    df_res = df_res.drop(drop_cols, axis=1)
    res_col_name = result_name or primary_col
    df_res[res_col_name] = res_col

    return df_res


def categorize_result(row: pd.Series, scanner: ScannerBase = None) -> str:
    """Categorize the result into a predefined check category.
    The main feature for the categorization is the scanner check id.
    If the scanner check id does not provide the necessary information,
    the category will be derived from the generic check id.

    :param row: a single check result (i.e. a row) as a pandas series
    :param scanner: the scanner, which created the result and will be used as fallback
    :return: the category of the check result
    """
    cat = None
    if scanner is not None:
        # try to further specify the category by using the scanner id information
        cat = scanner.categorize_check(row[Col.ScannerCheckId])
    if cat is None:  # as fallback derive category from the check id
        cat = categorize_by_check_id(row[Col.CheckId])
    return cat


def drop_duplicates(df: pd.DataFrame) -> pd.DataFrame:
    """Remove duplicate results from the dataframe.
    A duplicate is identified on the basis of the scanner_check_id and the name of the scanned object.

    :param df: the dataframe from which the duplicates will be removed
    :return: a copy of the input dataframe without the duplicates
    """
    num_results = len(df)
    df_dedup = df.drop_duplicates(["scanner_check_id", "name"], ignore_index=True)
    num_removed = num_results - len(df_dedup)
    if num_removed > 0:
        logger.info(f"Dropped {num_removed} duplicates")
    return df_dedup


def categorize_by_check_id(check_id: Optional[str]) -> str:
    """
    Assign a category to the check depending on the prefix of the check id (i.e. the first part of the id)
    :param check_id: the id of the check which will be used for the categorization.
    :returns: the category as string
    """
    if check_id is None or pd.isnull(check_id):
        prefix = ""
    elif check_id.lower().startswith("pod-025"):
        return CheckCategory.DataSecurity  # secrets in env vars
    elif check_id.lower().startswith("pod-043"):  # Azure Cloud Credentials mounted
        return CheckCategory.DataSecurity
    elif check_id.lower().startswith("pod-045"):  # CVE-2021-25741
        return CheckCategory.Vulnerability
    elif check_id.lower().startswith("CM-002"):  # CVE-2021-25742
        return CheckCategory.Vulnerability
    elif check_id.lower().startswith("ing-005"):  # CVE-2021-25742
        return CheckCategory.Vulnerability
    elif check_id.lower().startswith("rel-004"):  # nodeSelector
        return CheckCategory.Segregation
    else:
        prefix = check_id.split("-")[0].lower().strip()


    if prefix in ["pod", "wl", "cj", "srv", "sc"]:
        return CheckCategory.Workload
    elif prefix in ["pss", "psa", "psp"]:
        return CheckCategory.AdmissionControl
    elif prefix == "rbac":
        return CheckCategory.IAM
    elif prefix in ["cm"]:  # currently only matches CM-001 but might need more granual distinction -> other prefix
        return CheckCategory.DataSecurity
    elif prefix in ["np", "ns"]:
        return CheckCategory.Segregation
    elif prefix in ["ing"]:
        return CheckCategory.Network 
    elif prefix in ["rel", "res"]:
        return CheckCategory.Reliability
    elif prefix == "inf":
        return CheckCategory.Infrastructure
    else:
        # if there is no valid check id then it defaults to the "misc" category
        return CheckCategory.Misc


def tabulate_manifests(manifests: list[cdk8s.Chart]) -> pd.DataFrame:
    """Convert a collection of generated manifests into a dataframe with the essential information as columns.

    :param manifests: the collection of manifests which will be converted
    :return: the meta information of the manifests as a dataframe
    """
    checks = []
    for chart in manifests:
        if not isinstance(chart, Check):
            continue

        checks.append(
            {
                Col.CheckId: chart.labels.get(CheckKey.CheckId, None),
                Col.Name: chart.name,
                Col.Expected: chart.meta.annotations.get(CheckKey.Expect, None),
                Col.Description: chart.meta.annotations.get(CheckKey.Description, None),
                Col.PathToCheck: chart.meta.annotations.get(CheckKey.CheckPath, None),
            }
        )
    return pd.DataFrame(checks)


def order_columns(df: pd.DataFrame) -> pd.DataFrame:
    """Re-order the most important columns in the given dataframe.
    :param df: the dataframe whose columns will be re-ordered
    :return: a copy of the dataframe with the columns in a predefined order.
    """
    ordered_cols = [
        Col.CheckId,
        Col.Name,
        Col.ScannerCheckId,
        Col.ScannerCheckName,
        Col.Expected,
        Col.Got,
        Col.Details,
        Col.Category,
    ]
    remaining_cols = [c for c in df.columns.tolist() if c not in ordered_cols]
    return df[ordered_cols + remaining_cols]


@lru_cache
def load_benchmark(with_categories: bool = False) -> pd.DataFrame:
    """
    Load the checks from the generated manifests, along with their id and additional meta information
    and return them in a tabular format
    :return: the meta information of the manifests as a dataframe
    """
    app = cdk8s.App()
    manifests = generate_manifests(app)

    df = tabulate_manifests(manifests)
    if with_categories:
        df[Col.Category] = df[Col.CheckId].map(categorize_by_check_id)
    return df


@dataclass
class EvaluationSummary:
    version: str | None
    checks_per_category: dict
    score: float
    coverage: float
    extra_checks: int
    missing_checks: int

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict) -> "EvaluationSummary":
        return EvaluationSummary(**data)


def create_summary(df: pd.DataFrame, metric: Metric = Metric.F1, version: Optional[str] = None) -> EvaluationSummary:
    """
    Create a summary of the evaluation results.
    :param df: the dataframe containing the execution results
    :param metric: the metrics used for the calculation of the score
    :param version: the version of the tool when the results were created
    :returns: a summary of the evaluation
    """
    # note the only information from the scanner is the 'got' column which is required for the score calculation
    # all others infos from the scanners are dropped to avoid pollution of the results
    # e.g., having countless scanner_checks per benchmark check
    relevant_columns = [Col.CheckId, Col.Category, Col.ResultType, Col.Expected, Col.Got]
    df_unique_checks = df[relevant_columns].drop_duplicates(relevant_columns, ignore_index=True)

    # consolidate conflicting check results (e.g. TP, FP, ...) by taking the 'worst'
    # i.e., FP in case of both TP and FP
    df_unique_checks = (
        df_unique_checks.groupby(by=[Col.CheckId, Col.ResultType])
        .apply(_consolidate_conflicting_checks)
        .reset_index(drop=True)
    )

    # extra checks can have a huge impact on the score and coverage
    # and are outside of the benchmarks scope, distorting the true values
    df_no_extra = df_unique_checks[df_unique_checks[Col.ResultType] != ResultType.Extra]

    return EvaluationSummary(
        version,
        check_summary_per_category(df_unique_checks),
        calculate_score(df_no_extra, metric),
        calculate_coverage(df_no_extra),
        sum(df["result_type"] == ResultType.Extra),
        sum(df["result_type"] == ResultType.Missing),
    )


def _consolidate_conflicting_checks(df: pd.DataFrame):
    if len(df) == 1:
        return df
    else:
        return df[df[Col.Expected] != df[Col.Got]].head(1)


def check_summary_per_category(df: pd.DataFrame) -> dict:
    """
    Show the distribution of checks result types per category
    :param df: the dataframe which will be displayed
    :return: the summary of checks per category as dictionary
    """
    df_cat = df.groupby(["result_type"])["category"].value_counts().unstack(fill_value=0)
    return df_cat.to_dict()


class OverviewType(LowercaseStrEnum):
    Markdown = auto()
    Latex = auto()


def create_benchmark_overview(dest_dir: Path, format: OverviewType = OverviewType.Markdown) -> list[str]:
    """Create a markdown file 'benchmark-checks.md' with an overview of all the checks at the destination folder.
    If the file already exists, it will be overwritten.

    :param dest_dir: the folder where the file will be created
    """
    IMPLEMENTED_COL = "Implemented"
    df_bench = load_benchmark()
    df_bench[IMPLEMENTED_COL] = "yes"

    missing_checks = [
        {
            Col.CheckId: mc.id,
            Col.Name: mc.name,
            Col.Description: mc.description,
            Col.Expected: mc.expected,
            Col.PathToCheck: mc.checked_path,
        }
        for mc in MISSING_CHECKS
    ]
    df_missing_checks = pd.DataFrame(missing_checks)
    df_missing_checks[IMPLEMENTED_COL] = "no"

    # quality check: if an ID is in both dataframes, then it should be removed from MISSING_CHECKS
    misclassified_checks = _determine_misclassified_checks(df_bench, df_missing_checks)

    df = pd.concat([df_bench, df_missing_checks])

    # replace the '|' to avoid formatting issues in resulting markdown table
    df[Col.PathToCheck] = df[Col.PathToCheck].str.replace("|", "\n", regex=False)
    df = df.sort_values(by=Col.CheckId, ascending=True).rename(columns=snake_case_to_title)

    col_descriptions = {
        Col.CheckId: "The ID of the check for the benchmark",
        Col.Name: "The name of the check",
        Col.Expected: "The expected Result from a scanner. This should be either `alert` or `pass`",
        Col.Description: "A description for the relevancy of the check",
        Col.PathToCheck: "The path(s) to the field(s) on the resource which must be evaulated for this check",
        IMPLEMENTED_COL: "boolean flag, if this check is actually implemented for the benchmark",
        Col.Category: "The general category to which this checks belongs to. ",
    }

    with open(dest_dir / "benchmark-checks.md", "w") as f:
        f.write("# Benchmark Checks\n\n")
        for col_name, description in col_descriptions.items():
            f.write(f"- `{col_name.replace('_', ' ').title()}`: {description}\n")
        f.write("\n---\n")
        f.write(df.to_markdown())

    return misclassified_checks


def create_benchark_overview_latex_table() -> str:
    df_bench = load_benchmark(with_categories=True)

    tbl = df_bench.to_latex(
        caption="An overview of all generated checks and number of variants, grouped by their respective categories"
    )
    return tbl


def create_evaluation_summary(data_dir: str | Path = "./data", show_extra: bool = True) -> pd.DataFrame:
    """Load all evaluation results of all scanners as a dataframe
    :params data_dir: the global directory, where the scanner results are stored
    :param show_extra: if set, show the number of additional checks in parenthesis

    :return: a dataframe where every row corresponds to the information for a particular scanner
    """
    scanner_infos = []

    for name, scanner in SCANNERS.items():
        # TODO use local setting for the result file
        files = get_scanner_result_file_paths(name, data_dir=data_dir)

        if len(files) == 0:
            logger.warning(f"No result files for '{name}' found, so no summary can be loaded")
            summary = EvaluationSummary(None, {}, 0, 0, 0, 0)

        else:
            # default to the first file listed
            result_file = files[0]
            results = load_scanner_results_from_file(scanner, result_file)

            df = evaluate_scanner(scanner, results)
            summary = create_summary(df, version=get_version_from_result_file(result_file))

            categories = summary.checks_per_category

        scanner_info = ScannerInfo(
            name,
            image=scanner.IMAGE_URL,
            version=summary.version,
            score=summary.score,
            coverage=summary.coverage,
            ci_mode=scanner.CI_MODE,
            runs_offline=str(scanner.RUNS_OFFLINE),
            cat_network=get_category_sum(categories.get(CheckCategory.Network, None), show_extra=show_extra),
            cat_IAM=get_category_sum(categories.get(CheckCategory.IAM, None), show_extra=show_extra),
            cat_admission_ctrl=get_category_sum(
                categories.get(CheckCategory.AdmissionControl, None), show_extra=show_extra
            ),
            cat_data_security=get_category_sum(categories.get(CheckCategory.DataSecurity, None), show_extra=show_extra),
            # cat_supply_chain=_get_category_sum(categories.get(CheckCategory.Workload, None)),
            cat_reliability=get_category_sum(categories.get(CheckCategory.Reliability, None), show_extra=show_extra),
            cat_segregation=get_category_sum(categories.get(CheckCategory.Segregation, None), show_extra=show_extra),
            cat_vulnerability=get_category_sum(categories.get(CheckCategory.Vulnerability, None), show_extra=show_extra),
            cat_workload=get_category_sum(categories.get(CheckCategory.Workload, None), show_extra=show_extra),
            cat_misc=get_category_sum(
                categories.get(CheckCategory.Misc, {}) | categories.get(CheckCategory.Vulnerability, {}),
                show_extra=show_extra,
            ),
            can_scan_manifests=scanner.can_scan_manifests,
            can_scan_cluster=scanner.can_scan_cluster,
            custom_checks=str(scanner.CUSTOM_CHECKS),
            formats=", ".join(scanner.FORMATS),  # Ag Grid does not support lists
            is_valid_summary=summary is None,
        )
        scanner_infos.append(scanner_info)

    df = pd.DataFrame(scanner_infos)
    return df


def get_category_sum(category_summary: pd.Series | None, show_extra: bool = True) -> str:
    """Compress the information of the result types into a single string.

    :param category_summary: a series of all the result types of a particular scanner
    :param show_extra: if set, show the number of additional checks in parenthesis
    :return: the summary of the result types formatted as a string
    """
    if category_summary is None:
        covered, missing, extra = 0, 0, 0
    else:
        covered = category_summary.get(ResultType.Covered, 0)
        missing = category_summary.get(ResultType.Missing, 0)
        extra = category_summary.get(ResultType.Extra, 0)
    res = f"{covered}/{covered+missing}"
    if show_extra and extra > 0:
        res += f" (+{extra})"
    return res


def _determine_misclassified_checks(df_bench: pd.DataFrame, df_missing_checks: pd.DataFrame):
    missing_ids = tuple(df_missing_checks[Col.CheckId].unique())
    implemented_ids = df_bench[Col.CheckId].unique()
    misclassified_checks = [c for c in implemented_ids if c.startswith(missing_ids)]

    return misclassified_checks


def snake_case_to_title(text: str) -> str:
    """Convert a text in snake case to title case.
    E.g. `this_is_a_text` -> `This Is A Text`

    :param text: the text which will be transformed
    :return: the transformed text
    """
    return " ".join([t.title() for t in text.split("_")])
