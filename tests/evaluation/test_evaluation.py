from collections import namedtuple
from typing import Any

import numpy as np
import pandas as pd
import pytest
from loguru import logger as log

from kalm_benchmark.evaluation.evaluation import (
    Col,
    Metric,
    ResultType,
    _coalesce_columns,
    _compare_paths,
    _filter_redundant_extra_checks,
    _is_partial_match,
    calculate_score,
    categorize_by_check_id,
    categorize_result,
    create_summary,
    filter_out_of_scope_alerts,
    get_confusion_matrix,
    merge_dataframes,
)
from kalm_benchmark.evaluation.scanner.scanner_evaluator import (
    CheckCategory,
    CheckStatus,
    ScannerBase,
)

ConfusionMatrix = namedtuple("ConfusionMatrix", ["tp", "fp", "tn", "fn"])


@pytest.fixture
def df_full():
    return pd.DataFrame({"got": ["alert"] * 3 + ["pass"] * 2, "expected": ["alert", "pass", "alert", "alert", "pass"]})


@pytest.fixture
def caplog(caplog):
    # suppress default loggers and override caplog to capture loguru logs
    # https://github.com/Delgan/loguru/issues/59#issuecomment-1016516449
    log.remove()
    handler_id = log.add(caplog.handler, format="{message}")
    yield caplog
    log.remove(handler_id)


def gen_data(conf_mat: ConfusionMatrix) -> pd.DataFrame:
    tp, fp, tn, fn = conf_mat

    # create 2 different sets, with partial overlap to get a full confusion matrix
    # expect: |██████|█████████████ FN+TP ████████████████████████|░░TN+FP░░░|
    # got:    |░░FN░░|█████████████████████ TP ███████████████████|██TN██░FP░|
    # ░ = pass / █ = alert

    return pd.DataFrame(
        {
            "expected": ["alert"] * (fn + tp) + ["pass"] * (tn + fp),
            "got": ["pass"] * fn + ["alert"] * tp + ["pass"] * tn + ["alert"] * fp,
        }
    )


class TestResultSummarization:
    def test_summary_counts_distinct_benchmark_checks(self):
        category = "cat1"
        res_type = ResultType.Covered
        data = [
            {
                Col.CheckId: "POD-001",
                Col.ScannerCheckId: "check-1",
                Col.ResultType: res_type,
                Col.Category: category,
                Col.Expected: CheckStatus.Pass,
                Col.Got: CheckStatus.Pass,
            },
            {
                Col.CheckId: "POD-001",
                Col.ScannerCheckId: "check-2",
                Col.ResultType: res_type,
                Col.Category: category,
                Col.Expected: CheckStatus.Pass,
                Col.Got: CheckStatus.Pass,
            },
        ]

        df_in = pd.DataFrame(data)
        summary = create_summary(df_in)
        cat_results = summary.checks_per_category[category]
        # even though there are 2 entries as they both have the
        # same result type for the same check_id it counts as 1
        assert cat_results[res_type] == 1

    def test_summary_extra_checks_are_ignored_from_cat(self):
        category = "cat1"
        res_type = ResultType.Covered
        data = [
            {
                Col.CheckId: "POD-001",
                Col.ScannerCheckId: "check-1",
                Col.ResultType: ResultType.Covered,
                Col.Category: category,
                Col.Expected: CheckStatus.Pass,
                Col.Got: CheckStatus.Pass,
            },
            {
                Col.CheckId: "POD-001",
                Col.ScannerCheckId: "check-2",
                Col.ResultType: ResultType.Extra,
                Col.Category: category,
                Col.Expected: CheckStatus.Pass,
                Col.Got: CheckStatus.Pass,
            },
        ]

        df_in = pd.DataFrame(data)
        summary = create_summary(df_in)
        cat_results = summary.checks_per_category[category]
        # even though there are 2 entries as they both have the
        # same result type for the same check_id it counts as 1
        assert cat_results[res_type] == 1

    def test_summary_use_more_pessimistic_result_when_inconsistent(self):
        category = "cat1"
        res_type = ResultType.Covered
        data = [
            {
                Col.CheckId: "POD-001",
                Col.ScannerCheckId: "check-1",
                Col.ResultType: res_type,
                Col.Category: category,
                Col.Expected: CheckStatus.Pass,
                Col.Got: CheckStatus.Pass,
            },
            {
                Col.CheckId: "POD-001",
                Col.ScannerCheckId: "check-2",
                Col.ResultType: res_type,
                Col.Category: category,
                Col.Expected: CheckStatus.Alert,
                Col.Got: CheckStatus.Pass,
            },
        ]

        df_in = pd.DataFrame(data)
        summary = create_summary(df_in)
        cat_results = summary.checks_per_category[category]
        assert cat_results[res_type] == 1
        assert summary.score == pytest.approx(0.0)


class TestConfusionMatrix:
    def test_add_margins_by_default(self, df_full):
        df_xtab = get_confusion_matrix(df_full)
        assert len(df_xtab) == 3
        assert len(df_xtab.columns) == 3

    def test_disabling_margin_results_in_2_by_2_dataframe(self, df_full):
        df_xtab = get_confusion_matrix(df_full, margins=False)
        assert len(df_xtab) == 2
        assert len(df_xtab.columns) == 2

    def test_all_values_present(self, df_full):
        df_xtab = get_confusion_matrix(df_full, margins=False)
        expect = np.array([[2, 1], [1, 1]])

        np.testing.assert_array_equal(df_xtab.values, expect)

    def test_columns_are_scanner_alert_and_pass(self, df_full):
        df_xtab = get_confusion_matrix(df_full, margins=False)
        # order of columns is also important
        assert df_xtab.columns.tolist() == ["scanner alert", "scanner pass"]

    def test_rows_are_actual_alert_and_pass(self, df_full):
        df_xtab = get_confusion_matrix(df_full, margins=False)
        # order of rows is also important
        assert df_xtab.index.tolist() == ["actual alert", "actual pass"]

    def test_show_actual_alerts_despite_none_present(self):
        df = pd.DataFrame({"got": ["pass"] * 5, "expected": ["alert", "pass", "alert", "alert", "pass"]})
        df_xtab = get_confusion_matrix(df, margins=False)
        expect = np.array(
            [
                [0, 3],  # actual alert
                [0, 2],  # actual pass
            ]
        )
        np.testing.assert_array_equal(df_xtab.values, expect)

    def test_show_actual_passes_despite_none_present(self):
        df = pd.DataFrame({"got": ["alert"] * 5, "expected": ["alert", "pass", "alert", "alert", "pass"]})
        df_xtab = get_confusion_matrix(df, margins=False)
        expect = np.array(
            [
                [3, 0],  # actual alert
                [2, 0],  # actual pass
            ]
        )
        np.testing.assert_array_equal(df_xtab.values, expect)

    def test_show_expected_alerts_despite_none_present(self):
        df = pd.DataFrame({"got": ["alert", "pass", "alert", "alert", "pass"], "expected": ["pass"] * 5})
        df_xtab = get_confusion_matrix(df, margins=False)
        expect = np.array(
            [
                [0, 0],  # actual alert
                [3, 2],  # actual pass
            ]
        )
        np.testing.assert_array_equal(df_xtab.values, expect)

    def test_show_expected_passes_despite_none_present(self):
        df = pd.DataFrame({"got": ["alert", "pass", "alert", "alert", "pass"], "expected": ["alert"] * 5})
        df_xtab = get_confusion_matrix(df, margins=False)
        expect = np.array(
            [
                [3, 2],  # actual alert
                [0, 0],  # actual pass
            ]
        )
        np.testing.assert_array_equal(df_xtab.values, expect)


class TestScoreCalculation:
    _conf_mat_combos = (
        "cm",
        [
            ConfusionMatrix(90, 5, 5, 0),
            ConfusionMatrix(10, 90, 5, 5),
            ConfusionMatrix(1, 0, 90, 0),
            ConfusionMatrix(1, 0, 0, 1000),
            ConfusionMatrix(1, 1, 1, 1),
            ConfusionMatrix(1, 0, 0, 0),  # at least TP has to be positive to avoid a DivBy0 exception
        ],
    )

    @staticmethod
    def _calc_f1(cm: ConfusionMatrix) -> float:
        precision = cm.tp / (cm.tp + cm.fp)
        recall = cm.tp / (cm.tp + cm.fn)
        return 2 * (precision * recall) / (precision + recall)

    def test_f1_metric_used_by_default(self):
        cm = ConfusionMatrix(90, 2, 1, 5)
        df = gen_data(cm)
        score = calculate_score(df)

        f1 = self._calc_f1(cm)
        assert score == pytest.approx(f1)

    @pytest.mark.parametrize(*_conf_mat_combos)
    def test_f1_metric(self, cm: ConfusionMatrix):
        df = gen_data(cm)
        score = calculate_score(df)

        f1 = self._calc_f1(cm)
        assert score == pytest.approx(f1)

    @pytest.mark.parametrize(*_conf_mat_combos)
    def test_accuracy_metric(self, cm: ConfusionMatrix):
        df = gen_data(cm)
        score = calculate_score(df, metric=Metric.Accuracy)

        accuracy = (cm.tp + cm.tn) / sum(cm)
        assert score == pytest.approx(accuracy)

    def test_faulty_data_is_handled_gracefully(self, caplog):
        # no TP -> means both precision and recall are 0
        # which in turn leads to division by 0 exception
        cm = ConfusionMatrix(0, 10, 10, 10)
        df = gen_data(cm)
        score = calculate_score(df)
        assert "not calculate F1" in caplog.text
        # the score itself should have a proper value
        assert score == pytest.approx(0.0)


class TestCoverageCalculation:
    pass


class TestColumnMerging:
    @pytest.fixture
    def dict_2_cols(self) -> dict:
        return {
            "primary": ["obj1", "obj2", "obj3"],
            "secondary": ["secondary1", "secondary2", "secondary3"],
        }

    def test_merge_primary_column_has_priorty(self, dict_2_cols):
        df = pd.DataFrame(dict_2_cols)
        result_col_name = "result"
        df_res = _coalesce_columns(df, primary_col="primary", secondary_col="secondary", result_name=result_col_name)
        assert list(df_res[result_col_name]) == dict_2_cols["primary"]

    def test_merge_secondary_column_is_fallback(self):
        primary_col = ["primary", None, np.nan, ""]
        secondary_col = ["this", "is", "the", "fallback"]
        df = pd.DataFrame({"primary": primary_col, "secondary": secondary_col})
        df_res = _coalesce_columns(df, primary_col="primary", secondary_col="secondary", result_name="result")
        assert list(df_res["result"]) == primary_col[:1] + secondary_col[1:]

    def test_use_explicit_result_column_name(self, dict_2_cols):
        df = pd.DataFrame(dict_2_cols)
        result_col_name = "name"
        df_res = _coalesce_columns(df, primary_col="primary", secondary_col="secondary", result_name=result_col_name)

        assert list(df_res.columns) == [result_col_name]

    def test_merge_does_not_alter_original(self, dict_2_cols):
        df = pd.DataFrame(dict_2_cols)
        _ = _coalesce_columns(df, "primary", "secondary")
        df_orig = pd.DataFrame(dict_2_cols)
        pd.testing.assert_frame_equal(df_orig, df)

    def test_use_primary_column_as_resulting_column_by_default(self, dict_2_cols):
        df = pd.DataFrame(dict_2_cols)
        primary_col_name = "primary"
        df_res = _coalesce_columns(df, primary_col=primary_col_name, secondary_col="secondary")
        assert list(df_res.columns) == [primary_col_name]

    def test_merge_columns_other_columns_are_not_affected(self, dict_2_cols):
        num_rows = len(dict_2_cols["primary"])
        aux_cols = {"other_col": ["misc"] * num_rows}
        df = pd.DataFrame({**dict_2_cols, **aux_cols})
        df_res = _coalesce_columns(df, primary_col="primary", secondary_col="secondary", result_name="name")

        res_cols = list(df_res.columns)
        assert all(aux_col in res_cols for aux_col in aux_cols.keys())


class TestResultCategorization:
    _FROM_CHECKID: str = "cat from check id"

    class _MockScanner(ScannerBase):
        _FROM_SCANNER: str = "cat from scanner"

        @classmethod
        def categorize_check(cls, id: str | None) -> str:
            if id is None:  # just an internal mechanic to get it to
                return None  # abstain from making a categorization
            return cls._FROM_SCANNER

    @staticmethod
    def _gen_row(check_id: str, scanner_check_id: str | None = None) -> pd.Series:
        return pd.Series({"check_id": check_id, "scanner_check_id": scanner_check_id})

    def test_unknown_id_results_in_misc_category(self):
        result = self._gen_row("a check-id")
        assert categorize_result(result) == CheckCategory.Misc

    def test_check_id_is_main_discriminator(self, mocker):
        mocker.patch("kalm_benchmark.evaluation.evaluation.categorize_by_check_id", return_value=self._FROM_CHECKID)
        result = self._gen_row("a check-id")
        assert categorize_result(result, self._MockScanner) == self._FROM_CHECKID

    def test_scanner_is_fallback_discriminator(self):
        result = self._gen_row("a check-id", "scanner check-id")
        assert categorize_result(result, self._MockScanner) == self._MockScanner._FROM_SCANNER

    def test_scanner_can_abstain_from_categorization(self):
        result = self._gen_row("a check-id", None)  # None triggers mock mechanic to return none as well
        assert categorize_result(result, self._MockScanner) == CheckCategory.Misc

    def test_fallback_is_optional(self, mocker):
        mocker.patch("kalm_benchmark.evaluation.evaluation.categorize_by_check_id", return_value=self._FROM_CHECKID)
        result = self._gen_row("a check-id")
        assert categorize_result(result, None) == self._FROM_CHECKID


class TestCheckCategorizationByCheckId:
    @pytest.mark.parametrize("id", ["POD-1", "pod-2", "PoD-3", " pod-bla", "pod"])
    def test_pod_security(self, id: str):
        cat = categorize_by_check_id(id)
        assert cat == CheckCategory.PodSecurity

    @pytest.mark.parametrize("id", ["PSP-1", "psp-2", "PsP-3", " psp--"])
    def test_pod_security_policy(self, id: str):
        cat = categorize_by_check_id(id)
        assert cat == CheckCategory.PSP

    @pytest.mark.parametrize("id", ["RBAC-1", "rbac-2", "RbAC-3", "rbac---"])
    def test_rbac(self, id: str):
        cat = categorize_by_check_id(id)
        assert cat == CheckCategory.RBAC

    @pytest.mark.parametrize("id", ["NS-1", "ns-2", "SRV-1", "WL-2", "CJ-1"])
    def test_workload_management(self, id: str):
        cat = categorize_by_check_id(id)
        assert cat == CheckCategory.Workload

    @pytest.mark.parametrize("id", ["NP-1", "np-2", "ING-1", "ing-2"])
    def test_networking(self, id: str):
        cat = categorize_by_check_id(id)
        assert cat == CheckCategory.Network

    @pytest.mark.parametrize("id", ["ARST-1", "MISC-1", "INVALID", "", None])
    def test_all_other_are_misc(self, id: str | None):
        cat = categorize_by_check_id(id)
        assert cat == CheckCategory.Misc


class TestOutOfScopeFilter:
    NAMESPACES = ["kalm-benchmark", "kube-system", "kube-public", "kube-node-lease", "local-path-storage"]

    def test_nothing_to_filter(self):
        df = pd.DataFrame(
            {
                "category": ["a", "valid", "cat"],
                "namespace": ["kalm-benchmark", "unrestricted", "other-ns"],
                "name": ["foo"] * 3,
            }
        )
        df_res = filter_out_of_scope_alerts(df)
        np.testing.assert_array_equal(df.values, df_res.values)

    @pytest.mark.parametrize("drop_col", ["category", "namespace", "name"])
    def test_missing_required_columns_handled_gracefully(self, caplog, drop_col: str):
        df = pd.DataFrame(
            {
                "category": ["cat"] * 2,
                "namespace": ["kube-system", "kube-bench"],
                "name": ["foo"] * 2,
            }
        )
        df = df.drop(drop_col, axis=1)
        df_res = filter_out_of_scope_alerts(df)
        assert drop_col in caplog.text
        # no filter was applied -> output is the original dataframe
        np.testing.assert_array_equal(df.values, df_res.values)

    def test_is_special_namespace(self):
        num_ns = len(self.NAMESPACES)
        df = pd.DataFrame(
            {
                "category": ["cat"] * num_ns,
                "namespace": ["-"] * num_ns,
                "name": self.NAMESPACES,
            }
        )
        df_res = filter_out_of_scope_alerts(df)
        assert len(df_res) == 1
        df_expect = df[df["name"] == "kalm-benchmark"]
        np.testing.assert_array_equal(df_expect.values, df_res.values)

    def test_contained_in_special_namespace(self):
        num_ns = len(self.NAMESPACES)
        df = pd.DataFrame(
            {
                "category": ["cat"] * num_ns,
                "namespace": self.NAMESPACES,
                "name": ["foo"] * num_ns,
            }
        )
        df_res = filter_out_of_scope_alerts(df)
        assert len(df_res) == 1
        df_expect = df[df["namespace"] == "kalm-benchmark"]
        np.testing.assert_array_equal(df_expect.values, df_res.values)

    def test_infra_checks_are_always_in_scope(self):
        num_ns = len(self.NAMESPACES)
        num_infra = num_ns - 1
        df = pd.DataFrame(
            {
                "category": [CheckCategory.Infrastructure] * num_infra + ["cat"],
                "namespace": self.NAMESPACES,
                "name": ["foo"] * num_ns,
            }
        )
        df_res = filter_out_of_scope_alerts(df)
        df_expect = df[df["category"] == CheckCategory.Infrastructure]
        assert len(df_res) == num_infra
        np.testing.assert_array_equal(df_expect.values, df_res.values)

    def test_clusterwide_objects_in_scope(df):
        num = 5
        df = pd.DataFrame(
            {
                "category": ["RBAC"] * num,
                "namespace": [None] * num,
                "name": ["foo"] * num,
            }
        )
        df_res = filter_out_of_scope_alerts(df)
        assert len(df_res) == num
        # none should be filtered
        np.testing.assert_array_equal(df_res.values, df.values)


def assert_dfs_are_equal(
    df_expect: pd.DataFrame,
    df_res: pd.DataFrame,
    col_order: None | list[str] = None,
    sort_cols: None | list[str] = None,
    NAN_VALUE: None | Any = None,
) -> bool:
    if NAN_VALUE is not None:
        df_expect = df_expect.fillna(NAN_VALUE)
        df_res = df_res.fillna(NAN_VALUE)

    if sort_cols is not None:
        df_expect = df_expect.sort_values(by=sort_cols)
        df_res = df_res.sort_values(by=sort_cols)

    if col_order is None:
        col_order = df_expect.columns

    df_expect = df_expect[col_order]
    df_res = df_res[col_order]

    np.testing.assert_array_equal(df_expect.values, df_res.values)


class TestDataframeMerge:
    def test_merge_on_single_column_no_missing(self):
        pk = ["a", "b", "c"]
        left_data = [1, 2, 3]
        right_data = [100, 200, 300]
        df1 = pd.DataFrame({"pk": pk, "left": left_data})
        # use inverse order of pk column to ensure it's a proper merge
        df2 = pd.DataFrame({"pk": pk[::-1], "right": right_data[::-1]})

        df_res = merge_dataframes(df1, df2, id_column="pk")
        df_expect = pd.DataFrame({"pk": pk, "left": left_data, "right": right_data})

        # no needless columns are added as side effect
        assert len(df_res.columns) == 3
        assert_dfs_are_equal(df_expect, df_res)
        np.testing.assert_array_equal(df_res.values, df_expect.values)

    def test_no_information_is_lost_if_no_full_match(self):
        pk_left = ["a", "b", "c"]
        data_left = [1, 2, 3]
        pk_right = ["a", "x", "y"]
        data_right = [10, 20, 30]

        df1 = pd.DataFrame({"pk": pk_left, "left": data_left})
        df2 = pd.DataFrame({"pk": pk_right, "right": data_right})
        # use 0 as NaN value to avoid problems with numpyas assertion function,
        # which always fails when NaNs are in it, despite being the same in both
        df_res = merge_dataframes(df1, df2, id_column="pk")

        df_expect = pd.DataFrame(
            {
                "pk": pk_left + pk_right[1:],
                "left": data_left + [None] * 2,
                "right": data_right[:1] + [None] * 2 + data_right[1:],
            }
        )
        assert_dfs_are_equal(df_expect, df_res, sort_cols=["pk", "left"], NAN_VALUE=0)

    def test_merge_on_two_cols_simple(self):
        NAN_VAL = 0
        pk_left = ["a", "a", "b", "b"]
        sk_left = [".1", ".2", ".1", ".2"]
        data_left = [1, 2, 3, 4]
        pk_right = ["a", "a", "c", "c"]
        sk_right = [".1", ".3", ".1", ".2"]
        data_right = [10, 20, 30, 40]

        df1 = pd.DataFrame({"pk": pk_left, "sk": sk_left, "left": data_left})
        df2 = pd.DataFrame({"pk": pk_right, "sk": sk_right, "right": data_right})

        df_res = merge_dataframes(df1, df2, id_column="pk", path_columns="sk")

        # only 1st row  is a match -> the other rows are extra
        extra_rows = len(pk_right) - 1
        df_expect = pd.DataFrame(
            {
                "pk": pk_left + ["a", "c", "c"],
                "sk": sk_left + sk_right[1:],
                "left": data_left + [NAN_VAL] * extra_rows,
                "right": data_right[:1] + [NAN_VAL] * extra_rows + data_right[1:],
            }
        )
        assert_dfs_are_equal(df_expect, df_res, sort_cols=["pk", "sk"], NAN_VALUE=NAN_VAL)

    def test_merge_on_two_cols_reslting_paths_is_updated_to_matching_path(self):
        pk = ["a"]
        df1 = pd.DataFrame({"pk": pk, "sk": [".1|.2"]})
        df2 = pd.DataFrame({"pk": pk, "sk": [".2|.3"]})

        df_res = merge_dataframes(df1, df2, id_column="pk", path_columns="sk")
        df_expect = pd.DataFrame(
            {
                "pk": pk,
                "sk": ".2",  # only this path is present in both dfs
            }
        )
        assert_dfs_are_equal(df_expect, df_res, sort_cols=["pk", "sk"], NAN_VALUE=-1)

    def test_merge_on_two_cols_different_names(self):
        NAN_VAL = 0
        pk_left = ["a", "a", "b", "b"]
        sk_left = [".1", ".2", ".1", ".2"]
        data_left = [1, 2, 3, 4]
        pk_right = ["a", "a", "c", "c"]
        sk_right = [".1", ".3", ".1", ".2"]
        data_right = [10, 20, 30, 40]

        df1 = pd.DataFrame({"pk": pk_left, "sk_left": sk_left, "left": data_left})
        df2 = pd.DataFrame({"pk": pk_right, "sk_right": sk_right, "right": data_right})

        df_res = merge_dataframes(df1, df2, id_column="pk", path_columns=["sk_left", "sk_right"])

        # only 1st row  is a match -> the other rows are first from df_left then from df_right
        extra_rows = len(pk_right) - 1
        df_expect = pd.DataFrame(
            {
                "pk": pk_left + ["a", "c", "c"],
                "sk_left": sk_left + [NAN_VAL] * extra_rows,
                "sk_right": sk_left[:1] + [NAN_VAL] * extra_rows + sk_right[1:],
                "left": data_left + [NAN_VAL] * extra_rows,
                "right": data_right[:1] + [NAN_VAL] * extra_rows + data_right[1:],
            }
        )
        assert_dfs_are_equal(df_expect, df_res, sort_cols=["pk", "sk_left"], NAN_VALUE=NAN_VAL)

    def test_missing_paths_can_match(self):
        NAN_VAL = 0
        pk_left = ["a", "a", "b"]
        sk_left = [".1", ".2", None]
        data_left = [1, 2, 3]
        pk_right = ["a", "a", "b"]
        sk_right = [".1", None, None]
        data_right = [10, 20, 30]

        df1 = pd.DataFrame({"pk": pk_left, "sk": sk_left, "left": data_left})
        df2 = pd.DataFrame({"pk": pk_right, "sk": sk_right, "right": data_right})

        df_res = merge_dataframes(df1, df2, id_column="pk", path_columns="sk")

        # only 1st row  is a match -> the other rows are extra
        df_expect = pd.DataFrame(
            {
                "pk": ["a", "a", "a", "b"],
                "sk": [".1", ".2", NAN_VAL, "-"],
                "left": [1, 2, NAN_VAL, 3],
                "right": [10, NAN_VAL, 20, 30],
            }
        )
        assert_dfs_are_equal(df_expect, df_res, sort_cols=["pk", "sk"], NAN_VALUE=NAN_VAL)

    def test_merge_on_2_cols_multiple_sk_in_one_df(self):
        df1 = pd.DataFrame({"pk": ["a"], "sk": [".1|.2|.3|.4"], "left": [100]})
        pk_right = ["a", "a", "b"]
        sk_right = [".2", ".9", ".1"]
        data_right = [1, 2, 3]
        df2 = pd.DataFrame({"pk": pk_right, "sk": sk_right, "right": data_right})

        df_res = merge_dataframes(df1, df2, id_column="pk", path_columns="sk")
        df_expect = pd.DataFrame(
            {
                "pk": pk_right,
                "sk": sk_right,
                "left": [100, None, None],  # only the 1st roow of right df matches
                "right": data_right,
            }
        )
        assert_dfs_are_equal(df_expect, df_res, sort_cols=["pk", "sk"], NAN_VALUE=0)

    def test_merge_on_2_cols_multible_in_both_dfs(self):
        NAN_VAL = -1
        df1 = pd.DataFrame({"pk": ["a", "b"], "sk": [".1|.2", ".3|.4"], "left": [1, 2]})
        pk_right = ["a", "a", "a", "b"]
        sk_right = [".1|.2", ".1|.4", ".73", ".1"]
        data_right = [10, 20, 30, 40]
        df2 = pd.DataFrame({"pk": pk_right, "sk": sk_right, "right": data_right})

        df_res = merge_dataframes(df1, df2, id_column="pk", path_columns="sk")
        df_res = df_res.fillna(NAN_VAL)
        # 'b' is not a match
        df_expect = pd.DataFrame(
            {
                # only a's match
                "pk": ["a", "a", "a", "b", "b"],
                "sk": [".1|.2", ".1", ".73", ".1", ".3|.4"],
                "left": [1, 1, NAN_VAL, NAN_VAL, 2],
                "right": [10, 20, 30, 40, NAN_VAL],
            }
        )
        assert_dfs_are_equal(df_expect, df_res, sort_cols=["pk", "sk"], NAN_VALUE=NAN_VAL)

    def test_asymmetric_path_2_can_be_more_specific(self):
        col1, col2 = "p1", "p2"
        base_path = ".this.is.a.path"
        detailed_path = base_path + ".which.is.more.specific"
        row = pd.Series({col1: base_path, col2: detailed_path})
        res = _compare_paths(row, [col1, col2])
        assert res == detailed_path

    def test_path_comparison_is_case_insensitive(self):
        col1, col2 = "p1", "p2"
        ref_path = ".this.is.a.path"
        path = ref_path.upper()
        row = pd.Series({"p1": ref_path, col2: path})
        res = _compare_paths(row, [col1, col2])
        assert res == path

    def test_path_comparison_is_on_full_tokens(self):
        col1, col2 = "p1", "p2"
        path1 = ".spec.containers[].image"
        path2 = ".spec.containers[].imagePullPolicy"
        row = pd.Series({col1: path1, col2: path2})
        res = _compare_paths(row, [col1, col2])
        assert res == ""


class TestPartialPathMatching:
    def test_full_match(self):
        path = "this.is.a.path"
        assert _is_partial_match(path, path)

    def test_no_match(self):
        ref_path = "some.path"
        checked_path = "a.completely.different.path"
        assert not _is_partial_match(ref_path, checked_path)

    def test_checked_path_can_childpath_of_reference_path(self):
        ref_path = "this.is.a.path"
        checked_path = ref_path + ".sub.path"
        assert _is_partial_match(ref_path, checked_path)

    def test_checked_path_can_not_be_parent_path(self):
        checked_path = "this.is.a.path"
        ref_path = checked_path + ".sub.path"
        assert not _is_partial_match(ref_path, checked_path)

    def test_sibling_paths_with_same_start_string_are_not_a_match(self):
        base = ".spec.containers[]."
        ref_path = base + ".image"
        checked_path = base + ".imagePullPolicy"
        assert not _is_partial_match(ref_path, checked_path)

    def test_comparison_is_case_insensitive(self):
        ref_path = "THIS.is.A.Path"
        checked_path = "this.is.a.path"
        assert _is_partial_match(ref_path, checked_path)


class TestFilterOfRedundantExtraChecks:
    def test_only_rows_without_expected_status_are_filtered(self):
        df = pd.DataFrame({Col.Expected: [CheckStatus.Pass, CheckStatus.Alert, None], Col.Got: [CheckStatus.Pass] * 3})

        df_res = _filter_redundant_extra_checks(df)

        # the last row will be removed
        df_expect = df.iloc[:-1, :]
        assert_dfs_are_equal(df_expect, df_res)

    def test_only_checks_that_pass_are_filtered(self):
        df = pd.DataFrame({Col.Expected: [None] * 2, Col.Got: [CheckStatus.Alert, CheckStatus.Pass]})

        df_res = _filter_redundant_extra_checks(df)

        # the last row will be removed
        df_expect = df.iloc[:-1, :]
        assert_dfs_are_equal(df_expect, df_res)

    def test_checks_with_no_scanner_result_are_treated_as_pass(self):
        df = pd.DataFrame({Col.Expected: [CheckStatus.Pass, CheckStatus.Alert, None], Col.Got: [None] * 3})

        df_res = _filter_redundant_extra_checks(df)

        # the last row will be removed
        df_expect = df.iloc[:-1, :]
        assert_dfs_are_equal(df_expect, df_res)
