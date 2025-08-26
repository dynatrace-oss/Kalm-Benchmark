from dataclasses import asdict, dataclass, field
from enum import auto
from functools import lru_cache

# itertools.product import removed - no longer needed after merge simplification
from pathlib import Path
from typing import Optional

import cdk8s
import pandas as pd
from loguru import logger
from strenum import LowercaseStrEnum, SnakeCaseStrEnum, StrEnum

from kalm_benchmark.manifest_generator.check import Check
from kalm_benchmark.manifest_generator.constants import (
    MISSING_CHECKS,
    CheckKey,
    CheckStatus,
)
from kalm_benchmark.manifest_generator.gen_manifests import generate_manifests

from .category_mapping import get_category_by_prefix, get_category_by_specific_check
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
    cat_iam: str = "0/0"
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
    custom_checks: bool | str = False
    formats: list[str] = field(default_factory=list)
    is_valid_summary: bool = True
    latest_scan_date: str = "Never"


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
    labels = [CheckStatus.Alert, CheckStatus.Pass]
    if margins:
        labels.append(margins_name)

    df_xtab = df_xtab.reindex(
        index=labels,
        columns=labels,
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

    # Ensure column name consistency for merge operation
    # CheckResult objects create columns that match field names
    # The merge function expects both DataFrames to have consistent column naming

    # use the check id derived from the object name as fallback if none could be extracted from scanner
    check_id_pattern = r"^(\w+(?:-\d+)+)"  # match the first letters and then the numbers following it
    extracted_check_id = df_scanner["obj_name"].str.extract(check_id_pattern, expand=False)
    df_scanner["check_id"] = df_scanner["check_id"].fillna(extracted_check_id).str.upper()

    # use outer join to ensure coverage can be properly analysed
    df_bench = load_benchmark()
    df = merge_dataframes(df_bench, df_scanner, id_column=Col.CheckId)

    # Ensure all expected columns exist for downstream processing
    required_cols = [Col.PathToCheck, Col.CheckedPath, Col.ScannerCheckId, Col.ScannerCheckName]
    for col in required_cols:
        if col not in df.columns:
            df[col] = None  # Add missing columns with null values

    if not keep_redundant_checks:
        df = _filter_redundant_extra_checks(df)

    df = (
        df.pipe(_add_comparison_cols)
        .pipe(_coalesce_columns, primary_col="obj_name", secondary_col="name", result_name="name")
        .pipe(drop_duplicates)
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
    path_columns: Optional[str | list[str, str]] = None,
    keep_matched_paths: bool = False,
) -> pd.DataFrame:
    """Merge two dataframes on check ID with path matching support.

    :param df1: the benchmark dataframe
    :param df2: the scanner results dataframe
    :param id_column: column name to join on (typically check_id)
    :param path_columns: column name(s) containing paths to match on
    :param keep_matched_paths: whether to keep matched path information
    :return: merged dataframe
    """
    if path_columns is not None and isinstance(path_columns, str):
        # Handle path-aware merging
        return _merge_with_path_matching(df1, df2, id_column, path_columns)

    # Simple merge without path matching
    if isinstance(id_column, str):
        # Use suffixes to avoid column conflicts
        df = df1.merge(df2, on=id_column, how="outer", suffixes=("_bench", "_scanner"))

        # Find all columns that got suffixed due to conflicts
        all_suffixed_cols = [col for col in df.columns if col.endswith(("_bench", "_scanner"))]
        base_col_names = set()
        for col in all_suffixed_cols:
            if col.endswith("_bench"):
                base_col_names.add(col[:-6])  # Remove '_bench'
            elif col.endswith("_scanner"):
                base_col_names.add(col[:-8])  # Remove '_scanner'

        # Coalesce overlapping columns: prefer scanner data, fallback to benchmark
        for base_col in base_col_names:
            bench_col = f"{base_col}_bench"
            scanner_col = f"{base_col}_scanner"

            if bench_col in df.columns and scanner_col in df.columns:
                # Both columns exist - combine them (prefer scanner data)
                df[base_col] = df[scanner_col].combine_first(df[bench_col])
                df = df.drop(columns=[bench_col, scanner_col])
            elif bench_col in df.columns:
                # Only benchmark column exists
                df[base_col] = df[bench_col]
                df = df.drop(columns=[bench_col])
            elif scanner_col in df.columns:
                # Only scanner column exists
                df[base_col] = df[scanner_col]
                df = df.drop(columns=[scanner_col])

    else:
        # Handle tuple case (different column names in each dataframe)
        df = df1.merge(df2, left_on=id_column[0], right_on=id_column[1], how="outer", suffixes=("_bench", "_scanner"))

    return df


def _merge_with_path_matching(df1: pd.DataFrame, df2: pd.DataFrame, id_column: str, path_column: str) -> pd.DataFrame:
    """Merge dataframes with path matching logic for pipe-separated paths."""
    results = []

    # Get all unique check IDs from both dataframes
    all_ids = set(df1[id_column].dropna()) | set(df2[id_column].dropna())

    for check_id in all_ids:
        df1_rows = df1[df1[id_column] == check_id]
        df2_rows = df2[df2[id_column] == check_id]

        if df1_rows.empty and not df2_rows.empty:
            # Only in df2
            for _, row2 in df2_rows.iterrows():
                results.append(_combine_rows(None, row2, path_column))
        elif not df1_rows.empty and df2_rows.empty:
            # Only in df1
            for _, row1 in df1_rows.iterrows():
                results.append(_combine_rows(row1, None, path_column))
        elif not df1_rows.empty and not df2_rows.empty:
            # In both - need path matching
            matched_pairs = set()

            for _, row1 in df1_rows.iterrows():
                for _, row2 in df2_rows.iterrows():
                    if _paths_match(row1.get(path_column), row2.get(path_column)):
                        results.append(_combine_rows(row1, row2, path_column))
                        matched_pairs.add((row1.name, row2.name))

            # Add unmatched rows from df1
            for _, row1 in df1_rows.iterrows():
                if not any(pair[0] == row1.name for pair in matched_pairs):
                    results.append(_combine_rows(row1, None, path_column))

            # Add unmatched rows from df2
            for _, row2 in df2_rows.iterrows():
                if not any(pair[1] == row2.name for pair in matched_pairs):
                    results.append(_combine_rows(None, row2, path_column))

    return pd.DataFrame(results) if results else pd.DataFrame()


def _paths_match(path1, path2):
    """Check if two paths match, handling pipe-separated multiple paths."""
    if pd.isna(path1) or pd.isna(path2):
        return pd.isna(path1) and pd.isna(path2)

    if path1 == path2:
        return True

    # Handle pipe-separated paths
    paths1 = str(path1).split("|") if "|" in str(path1) else [str(path1)]
    paths2 = str(path2).split("|") if "|" in str(path2) else [str(path2)]

    # Check if any path from paths1 matches any path from paths2
    for p1 in paths1:
        for p2 in paths2:
            if p1.strip() == p2.strip():
                return True

    return False


def _combine_rows(row1, row2, path_column):
    """Combine two rows from different dataframes."""
    if row1 is None:
        return row2.to_dict()
    elif row2 is None:
        return row1.to_dict()
    else:
        # Both exist - combine them (prefer row2 for conflicts, row1 for path)
        combined = row1.to_dict()
        for col, val in row2.items():
            if col not in combined or pd.isna(combined[col]):
                combined[col] = val
            elif col == path_column:
                # For path column, use the more specific path
                combined[col] = val if not pd.isna(val) else combined[col]
        return combined


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


# Path comparison functions removed - simplified merge no longer needs complex path matching


def _add_comparison_cols(df: pd.DataFrame) -> pd.DataFrame:
    # the 2 "compare" columns columns are temporary analysis instruments and are bound to be removed
    # Since we simplified the merge, expected_2 no longer exists - just check if expected column exists
    compare_name = df["obj_name"] == df["name"] if "name" in df.columns else pd.Series([False] * len(df))
    compare_expected = pd.Series([True] * len(df))  # Always true since we only have one expected column now
    return df.assign(compare_name=compare_name, compare_expected=compare_expected)


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


def categorize_result(row: pd.Series, scanner: ScannerBase | None = None) -> str:
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
    Uses configuration-driven approach to reduce cognitive complexity.

    :param check_id: the id of the check which will be used for the categorization.
    :returns: the category as string
    """
    if check_id is None or pd.isnull(check_id):
        return CheckCategory.Misc

    # Check for specific mappings first (overrides prefix-based categorization)
    specific_category = get_category_by_specific_check(check_id)
    if specific_category:
        return specific_category

    # Extract prefix and use configuration-driven mapping
    prefix = check_id.split("-")[0].lower().strip()
    return get_category_by_prefix(prefix)


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
    ccss_alignment_score: Optional[float] = None
    ccss_correlation: Optional[float] = None
    total_ccss_findings: Optional[int] = None

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


def create_benchmark_overview(dest_dir: Path) -> list[str]:
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


def create_benchmark_overview_latex_table() -> str:
    df_bench = load_benchmark(with_categories=True)

    tbl = df_bench.to_latex(
        caption="An overview of all generated checks and number of variants, grouped by their respective categories"
    )
    return tbl


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
