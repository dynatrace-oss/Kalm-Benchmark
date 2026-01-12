from dataclasses import asdict, dataclass, field
from enum import auto
from functools import lru_cache
import json
from pathlib import Path

import cdk8s
import pandas as pd
from loguru import logger
from strenum import LowercaseStrEnum, SnakeCaseStrEnum, StrEnum

from kalm_benchmark.manifest_generator.check import Check
from kalm_benchmark.manifest_generator.constants import (
    MISSING_CHECKS,
    CheckKey,
    CheckStatus,
    StandardsFields,
)
from kalm_benchmark.manifest_generator.gen_manifests import generate_manifests
from kalm_benchmark.utils.constants import (
    MAX_EXPECTED_CHECKS,
    MAX_EXPECTED_RESOURCES,
    MAX_RISK_SCORE,
    SEVERITY_WEIGHTS,
)

from ..utils.category_mapping import (
    get_category_by_prefix,
    get_category_by_specific_check,
)
from .scanner.scanner_evaluator import CheckCategory, CheckResult, ScannerBase

pd.set_option("future.no_silent_downcasting", True)


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
    Standards = auto()
    CcssScore = auto()
    CcssSeverity = auto()
    BenchmarkId = auto()


@dataclass
class ScannerInfo:
    # note: the order of the fields dictates the initial order of the columns in the UI
    name: str
    image: str | None = None
    version: str | None = None
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
    logger.info("Confusion matrix:\n {df_xtab}", df_xtab=df_xtab)

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
) -> pd.DataFrame | None:
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
    check_id_pattern = r"^(\w+(?:-\d+)+)"
    extracted_check_id = df_scanner["obj_name"].str.extract(check_id_pattern, expand=False)

    df_scanner["check_id"] = df_scanner["check_id"].infer_objects(copy=False).fillna(extracted_check_id)
    df_scanner["check_id"] = df_scanner["check_id"].astype(str).str.upper().replace("NONE", None)
    df_scanner["benchmark_id"] = df_scanner["check_id"].str.extract(r"^([A-Z]+-\d+)", expand=False)

    df_bench = load_benchmark()
    df_bench["check_id"] = df_bench["check_id"].astype(str).str.upper().replace("NONE", None)
    df_bench["benchmark_id"] = df_bench["check_id"].str.extract(r"^([A-Z]+-\d+)", expand=False)
    df = merge_dataframes(df_bench, df_scanner, id_column=Col.CheckId, path_column_1="path_to_check", path_column_2=scanner.PATH_COLUMNS[0] if scanner.PATH_COLUMNS else None)

    required_cols = [Col.PathToCheck, Col.CheckedPath, Col.ScannerCheckId, Col.ScannerCheckName]
    for col in required_cols:
        if col not in df.columns:
            df[col] = None

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
    path_column_1: str | None = None,
    path_column_2: str | None = None,
) -> pd.DataFrame:
    """Merge two dataframes on check ID with path matching support.

    :param df1: the benchmark dataframe
    :param df2: the scanner results dataframe
    :param id_column: column name to join on (typically check_id)
    :param path_columns: column name(s) containing paths to match on
    :param keep_matched_paths: whether to keep matched path information
    :return: merged dataframe
    """
    if path_column_1 is not None and path_column_2 is not None:
        return _merge_with_path_matching(df1, df2, id_column, path_column_1, path_column_2)

    if isinstance(id_column, str):
        df = df1.merge(df2, on=id_column, how="outer", suffixes=("_bench", "_scanner"))
        all_suffixed_cols = [col for col in df.columns if col.endswith(("_bench", "_scanner"))]
        base_col_names = set()
        for col in all_suffixed_cols:
            if col.endswith("_bench"):
                base_col_names.add(col[:-6])  # Remove '_bench'
            elif col.endswith("_scanner"):
                base_col_names.add(col[:-8])  # Remove '_scanner'

        for base_col in base_col_names:
            bench_col = f"{base_col}_bench"
            scanner_col = f"{base_col}_scanner"

            if bench_col in df.columns and scanner_col in df.columns:
                df[base_col] = df[scanner_col].combine_first(df[bench_col])
                df = df.drop(columns=[bench_col, scanner_col])
            elif bench_col in df.columns:
                df[base_col] = df[bench_col]
                df = df.drop(columns=[bench_col])
            elif scanner_col in df.columns:
                df[base_col] = df[scanner_col]
                df = df.drop(columns=[scanner_col])

    else:
        # Handle tuple case (different column names in each dataframe)
        df = df1.merge(df2, left_on=id_column[0], right_on=id_column[1], how="outer", suffixes=("_bench", "_scanner"))

    return df


def _merge_with_path_matching(df1: pd.DataFrame, df2: pd.DataFrame, id_column: str, path_column_1: str, path_column_2: str) -> pd.DataFrame:
    """Merge dataframes with path matching logic for pipe-separated paths.
    Performs intelligent matching based on both ID and path columns,
    handling cases where paths are pipe-separated lists.

    :param df1: the first dataframe to merge
    :param df2: the second dataframe to merge
    :param id_column: the column name to use for initial grouping
    :param path_column: the column names containing paths for matching
    :return: the merged dataframe with matched rows combined
    """
    results = []

    # Get all unique check IDs from both dataframes
    all_ids = set(df1[id_column].dropna()) | set(df2[id_column].dropna())

    for check_id in all_ids:
        df1_rows = df1[df1[id_column] == check_id]
        df2_rows = df2[df2[id_column] == check_id]

        if df1_rows.empty and not df2_rows.empty:
            for _, row2 in df2_rows.iterrows():
                results.append(_combine_rows(None, row2))
        elif not df1_rows.empty and df2_rows.empty:
            for _, row1 in df1_rows.iterrows():
                results.append(_combine_rows(row1, None))
        elif not df1_rows.empty and not df2_rows.empty:
            matched_pairs = set()

            # first add all matching rows of the two datasets to a matched set
            for _, row1 in df1_rows.iterrows():
                for _, row2 in df2_rows.iterrows():
                    if _paths_match(row1.get(path_column_1), row2.get(path_column_2)):
                        results.append(_combine_rows(row1, row2))
                        matched_pairs.add((row1.name, row2.name))

            for _, row1 in df1_rows.iterrows():
                if not any(pair[0] == row1.name for pair in matched_pairs):
                    results.append(_combine_rows(row1, None))

            for _, row2 in df2_rows.iterrows():
                if not any(pair[1] == row2.name for pair in matched_pairs):
                    results.append(_combine_rows(None, row2))

    return pd.DataFrame(results) if results else pd.DataFrame()


def _paths_match(path1, path2):
    """Check if two paths match, handling pipe-separated multiple paths.
    Supports exact matching and cross-matching of pipe-separated path lists.

    :param path1: the first path or pipe-separated list of paths
    :param path2: the second path or pipe-separated list of paths
    :return: True if any path from path1 matches any path from path2
    """
    if pd.isna(path1) or pd.isna(path2):
        return pd.isna(path1) and pd.isna(path2)

    if path1 == path2:
        return True

    paths1 = str(path1).split("|") if "|" in str(path1) else [str(path1)]
    paths2 = str(path2).split("|") if "|" in str(path2) else [str(path2)]

    for p1 in paths1:
        for p2 in paths2:
            if p1.strip() == p2.strip():
                return True

    return False


def _combine_rows(row1, row2) -> dict:
    """Combine two rows from different dataframes, handling missing values.
    Merges row data by preferring non-null values from either row,
    with special handling for the specified path column.

    :param row1: the first row (pandas Series) or None
    :param row2: the second row (pandas Series) or None
    :return: a dictionary containing the combined row data
    """
    if row1 is None:
        return row2.to_dict()
    elif row2 is None:
        return row1.to_dict()
    else:
        combined = row1.to_dict()
        for col, val in row2.items():
            if col not in combined or pd.isna(combined[col]):
                combined[col] = val
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


def _add_comparison_cols(df: pd.DataFrame) -> pd.DataFrame:
    """Add temporary comparison columns for analysis purposes.
    The comparison columns are used for internal analysis and are expected to be removed later.

    :param df: the dataframe to which comparison columns will be added
    :return: the dataframe with additional comparison columns
    """
    # the 2 "compare" columns columns are temporary analysis instruments and are bound to be removed
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
    result_name: str | None = None,
) -> pd.DataFrame:
    """Merge two columns by preferring values from the primary column over the secondary column.
    Creates a new column that takes non-null values from the primary column first,
    falling back to the secondary column if the primary is null or empty.

    :param df: the dataframe containing the columns to merge
    :param primary_col: the name of the primary column (preferred values)
    :param secondary_col: the name of the secondary column (fallback values)
    :param result_name: optional name for the result column (defaults to primary_col)
    :return: the dataframe with the merged column and original columns removed
    """

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
    cat = categorize_by_check_id(row[Col.CheckId])
    if scanner is not None and cat is None:
        # try to further specify the category by using the scanner id information
        cat = scanner.categorize_check(row[Col.ScannerCheckId])
    # fallback to Misc
    if cat == None:
        print(f"Could not categorize check id '{row[Col.CheckId]}' with scanner id '{row[Col.ScannerCheckId]}', defaulting to Misc")
        return CheckCategory.Misc
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


def categorize_by_check_id(check_id: str | None) -> str | None:
    """
    Assign a category to the check depending on the prefix of the check id (i.e. the first part of the id)
    Uses configuration-driven approach to reduce cognitive complexity.

    :param check_id: the id of the check which will be used for the categorization.
    :returns: the category as string
    """
    if check_id is None or pd.isnull(check_id):
        return None

    # Check for specific mappings first (overrides prefix-based categorization)
    specific_category = get_category_by_specific_check(check_id)
    if specific_category:
        return specific_category

    # Extract prefix and use configuration-driven mapping
    prefix = check_id.split("-")[0].lower().strip()
    return get_category_by_prefix(prefix)


def _extract_standards(standards_str: str | None) -> dict[str, str]:
    """Extract standards from standards JSON string.
    
    :param standards_str: JSON string containing standards information
    :return: dict with formatted strings
    """
    if not standards_str or standards_str == "None":
        return {}

    try:
        standards_list = json.loads(standards_str.replace("'", "\""))  # Parse the JSON string
        
        if not isinstance(standards_list, list):
            return {standards_str: ""}

        formatted_items = dict()
        for standard in standards_list:
            if isinstance(standard, dict):
                name = standard.get(StandardsFields.standard.value, '')
                version = standard.get(StandardsFields.version.value, '')
                controls = standard.get(StandardsFields.controls.value, [])
                
                # Format as: "Standard Name (version): controls"
                item = name
                if version:
                    item += f" ({version})"

                control = ""
                if controls:
                    if isinstance(controls, list):
                        control += f"{'\n'.join(controls)}"
                    else:
                        control += f"{controls}"

                formatted_items[item] = control

        return formatted_items
    
    except (ValueError, SyntaxError):
        # If parsing fails, return the original string
        return {standards_str: ""}
    

def tabulate_manifests(manifests: list[cdk8s.Chart]) -> pd.DataFrame:
    """Convert a collection of generated manifests into a dataframe with the essential information as columns.

    :param manifests: the collection of manifests which will be converted
    :return: the meta information of the manifests as a dataframe
    """
    checks = []
    for chart in manifests:
        if not isinstance(chart, Check):
            continue
        
        check = dict()
        check[Col.CheckId] = chart.labels.get(CheckKey.CheckId, None)
        check[Col.Name] = chart.name
        check[Col.Expected] = chart.meta.annotations.get(CheckKey.Expect, None)
        check[Col.Description] = chart.meta.annotations.get(CheckKey.Description, None)
        check[Col.PathToCheck] = chart.meta.annotations.get(CheckKey.CheckPath, None)

        standards = _extract_standards(chart.meta.annotations.get(CheckKey.Standards, None))
        for standard_name in standards.keys():
            check[standard_name] = standards[standard_name]

        check[Col.CcssScore] = chart.meta.annotations.get(CheckKey.CcssScore, None)
        check[Col.CcssSeverity] = chart.meta.annotations.get(CheckKey.CcssSeverity, None)

        checks.append(check)
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


@lru_cache(maxsize=128)
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
    ccss_alignment_score: float | None = None
    ccss_correlation: float | None = None
    total_ccss_findings: int | None = None

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict) -> "EvaluationSummary":
        return EvaluationSummary(**data)


def unique_results_enriched_with_ccss(results: list[CheckResult], df: pd.DataFrame) -> list[CheckResult]:
    """Enrich the scan results with CCSS information from the benchmark dataframe.

    :param results: the collection of scan results
    :param df: the dataframe containing the benchmark information
    :return: a dataframe with enriched CCSS information
    """
    _, df_unique_checks_no_extra = consolidate_scan_evaluation_results(df)
    df_scanner_findings = (
        df_unique_checks_no_extra[
            (df_unique_checks_no_extra["scanner_check_id"] != "-") & 
            df_unique_checks_no_extra[Col.CcssScore].notnull()
        ]
        .groupby(["scanner_check_id", "severity"])
        .apply(_consolidate_conflicting_checks)
        .reset_index(drop=True)
    )

    findings_lookup = {
        row[Col.ScannerCheckId]: row
        for _, row in df_scanner_findings.iterrows()
    }

    unique_scan_checks = dict()

    for res in results:
        matching_row = findings_lookup.get(res.scanner_check_id)
        if matching_row is not None and pd.notna(matching_row[Col.CcssScore]):
            res.ccss_score = matching_row[Col.CcssScore]
            res.ccss_severity = matching_row[Col.CcssSeverity]
            if res.check_id and matching_row[Col.CheckId] == res.check_id.upper():
                unique_scan_checks[res.scanner_check_id] = res

    return list(unique_scan_checks.values())


def consolidate_scan_evaluation_results(df: pd.DataFrame) -> pd.DataFrame:
    """Consolidate scan evaluation results by grouping and aggregating.

    :param df: the dataframe containing the scan evaluation results
    :return: a consolidated dataframe with aggregated results
    """
    # note the only information from the scanner is the 'got' column which is required for the score calculation
    # all others infos from the scanners are dropped to avoid pollution of the results
    # e.g., having countless scanner_checks per benchmark check
    relevant_columns = [Col.BenchmarkId, Col.Category, Col.PathToCheck, Col.CheckedPath, Col.ResultType, Col.Expected, Col.Got]
    df_unique_checks = df.drop(df[df[Col.PathToCheck] == "-"].index).drop_duplicates(relevant_columns, ignore_index=True)

    # consolidate conflicting check results (e.g. TP, FP, ...) by taking the 'best'
    # i.e., TP in case of both TP and FP
    df_unique_checks = (
        df_unique_checks.groupby(by=[Col.BenchmarkId])
        .apply(_consolidate_conflicting_checks)
        .reset_index(drop=True)
    )

    # extra checks can have a huge impact on the score and coverage
    # and are outside of the benchmarks scope, distorting the true values
    df_no_extra = df_unique_checks[df_unique_checks[Col.ResultType] != ResultType.Extra]

    return df_unique_checks, df_no_extra


def create_summary(df: pd.DataFrame, metric: Metric = Metric.F1, version: str | None = None) -> EvaluationSummary:
    """
    Create a summary of the evaluation results.

    :param df: the dataframe containing the execution results
    :param metric: the metrics used for the calculation of the score
    :param version: the version of the tool when the results were created
    :returns: a summary of the evaluation
    """

    df_unique_checks, df_no_extra = consolidate_scan_evaluation_results(df)

    return EvaluationSummary(
        version,
        check_summary_per_category(df_unique_checks),
        calculate_score(df_no_extra, metric),
        calculate_coverage(df_no_extra),
        sum(df["result_type"] == ResultType.Extra),
        sum(df["result_type"] == ResultType.Missing),
    )


def _consolidate_conflicting_checks(df: pd.DataFrame):
    """Consolidate conflicting check results by selecting the best case scenario.
    When multiple results exist for the same check, prioritize cases where
    the expected result matches the actual result (i.e., true positives/negatives).

    :param df: the dataframe containing potentially conflicting check results
    :return: a single row representing the consolidated result
    """
    if len(df) == 1:
        return df
    else:
        return df.sort_values(by=[Col.ResultType, Col.Expected, Col.Got, Col.CheckId, Col.Category], ascending=True).head(1)


def check_summary_per_category(df: pd.DataFrame) -> dict:
    """Show the distribution of checks result types per category

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
    :param format: the output format type (Markdown or Latex)
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
    
    df = df.sort_values(by=Col.CheckId, ascending=True).rename(columns=snake_case_to_title).fillna("")

    col_descriptions = {
        Col.CheckId: "The ID of the check for the benchmark",
        Col.Name: "The name of the check",
        Col.Expected: "The expected Result from a scanner. This should be either `alert` or `pass`",
        Col.Description: "A description for the relevancy of the check",
        Col.PathToCheck: "The path(s) to the field(s) on the resource which must be evaulated for this check",
        IMPLEMENTED_COL: "boolean flag, if this check is actually implemented for the benchmark",
        Col.Category: "The general category to which this checks belongs to. ",
        Col.Standards: "Security standards and compliance frameworks that this check addresses",
    }

    with open(dest_dir / "benchmark-checks.md", "w") as f:
        f.write("# Benchmark Checks\n\n")
        for col_name, description in col_descriptions.items():
            f.write(f"- `{col_name.replace('_', ' ').title()}`: {description}\n")
        f.write("\n---\n")
        f.write(df.to_markdown())

    return misclassified_checks


def create_benchmark_overview_latex_table() -> str:
    """Create a LaTeX table with an overview of all benchmark checks grouped by categories.

    :return: a LaTeX table string with benchmark check overview
    """
    df_bench = load_benchmark(with_categories=True)

    tbl = df_bench.fillna("-").to_latex(
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
    """Identify checks that are marked as missing but are actually implemented.
    This quality check helps detect inconsistencies between the benchmark checks
    and the missing checks configuration.

    :param df_bench: the dataframe containing implemented benchmark checks
    :param df_missing_checks: the dataframe containing supposedly missing checks
    :return: a list of check IDs that are misclassified as missing
    """
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


def evaluate_helm_chart_scanner(
    scanner: ScannerBase,
    results: list[CheckResult],
) -> EvaluationSummary | None:
    """
    Evaluate scanner results specifically for Helm chart scans.
    Unlike benchmark evaluation, this focuses on findings distribution and coverage.

    :param scanner: the scanner instance
    :param results: the collection of helm chart scan results
    :return: evaluation summary adapted for helm chart context
    """
    if len(results) == 0:
        return None

    # Convert CheckResult objects to DataFrame
    result_data = []
    for result in results:
        result_data.append(
            {
                "scanner_check_id": getattr(result, "scanner_check_id", ""),
                "scanner_check_name": getattr(result, "scanner_check_name", ""),
                "severity": getattr(result, "severity", ""),
                "kind": getattr(result, "kind", ""),
                "obj_name": getattr(result, "obj_name", ""),
                "got": getattr(result, "got", "alert"),
            }
        )

    df_scanner = pd.DataFrame(result_data)

    # Calculate meaningful coverage based on Kubernetes resource types covered
    total_findings = len(results)
    unique_check_types = (
        df_scanner["scanner_check_name"].nunique() if not df_scanner["scanner_check_name"].isna().all() else 0
    )
    unique_resource_types = df_scanner["kind"].nunique() if not df_scanner["kind"].isna().all() else 0

    # Coverage based on check diversity and resource type diversity
    # Normalize to 0-1 scale: more unique checks and resource types = better coverage
    check_diversity = min(1.0, unique_check_types / MAX_EXPECTED_CHECKS)
    resource_diversity = min(1.0, unique_resource_types / MAX_EXPECTED_RESOURCES)
    coverage = (check_diversity + resource_diversity) / 2.0  # Average of both factors

    checks_per_category = _check_category(df_scanner, scanner)

    # Calculate a risk-based score (0-1 scale, lower risk = higher score)
    high_severity_count = sum(
        1
        for r in results
        if getattr(r, "severity", "") and getattr(r, "severity", "").upper() in ["HIGH", "CRITICAL", "DANGER"]
    )
    medium_severity_count = sum(
        1 for r in results if getattr(r, "severity", "") and getattr(r, "severity", "").upper() in ["MEDIUM", "WARNING"]
    )

    risk_penalty = (high_severity_count * SEVERITY_WEIGHTS["HIGH"]) + (
        medium_severity_count * SEVERITY_WEIGHTS["MEDIUM"]
    )
    risk_score = max(0.0, MAX_RISK_SCORE - risk_penalty) / MAX_RISK_SCORE

    return EvaluationSummary(
        version=getattr(scanner, "NAME", "unknown"),
        checks_per_category=checks_per_category if checks_per_category is not None else {},
        score=risk_score,
        coverage=coverage,
        extra_checks=total_findings,  # All helm findings are "extra" compared to benchmark
        missing_checks=0,  # Not applicable for helm charts
        ccss_alignment_score=None,  # Compute later when CCSS data available
        ccss_correlation=None,
        total_ccss_findings=total_findings,
    )


def _check_category(df_scanner: pd.DataFrame, scanner: ScannerBase):
    """Categorize scanner findings by check category and count occurrences.
    Uses the scanner's categorization method if available, otherwise falls back
    to pattern-based categorization.

    :param df_scanner: the dataframe containing scanner results
    :param scanner: the scanner instance used for categorization
    :return: a dictionary mapping categories to finding counts and unique check counts
    """
    checks_per_category = {}
    for category in CheckCategory:
        category_findings = []
        for _, result in df_scanner.iterrows():
            if hasattr(scanner, "categorize_check"):
                check_category = scanner.categorize_check(result.get("scanner_check_id", ""))
                if check_category == category.value:
                    category_findings.append(result)
            else:
                # Fallback categorization based on check name patterns
                check_name = result.get("scanner_check_name", "").lower()
                if _categorize_by_pattern(check_name, category):
                    category_findings.append(result)

        checks_per_category[category.value] = {
            "findings": len(category_findings),
            "unique_checks": len(([r.get("scanner_check_name", "") for r in category_findings])),
        }
    return checks_per_category


def _categorize_by_pattern(check_name: str, category: CheckCategory) -> bool:
    """Categorize a check by matching patterns in the check name.
    Uses predefined patterns for each category to determine if a check belongs to that category.

    :param check_name: the name of the check to categorize
    :param category: the category to test against
    :return: True if the check name matches patterns for the given category
    """
    patterns = {
        CheckCategory.AdmissionControl: ["admission", "policy", "psp", "securitycontext"],
        CheckCategory.DataSecurity: ["secret", "configmap", "sensitive", "credential", "token"],
        CheckCategory.IAM: ["rbac", "serviceaccount", "role", "permission", "access"],
        CheckCategory.Network: ["network", "ingress", "service", "port", "traffic"],
        CheckCategory.Reliability: ["resource", "limit", "probe", "readiness", "liveness"],
        CheckCategory.Segregation: ["namespace", "isolation", "tenant"],
        CheckCategory.Vulnerability: ["cve", "vulnerability", "image", "scan"],
        CheckCategory.Workload: ["pod", "deployment", "container", "workload"],
        CheckCategory.Infrastructure: ["node", "cluster", "storage", "volume"],
    }

    category_patterns = patterns.get(category, [])
    return any(pattern in check_name for pattern in category_patterns)
