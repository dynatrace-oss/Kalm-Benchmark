import json
from dataclasses import dataclass
from unittest.mock import MagicMock, patch

import pytest

from kalm_benchmark.utils.constants import UpdateType
from kalm_benchmark.evaluation.scanner.scanner_evaluator import (
    RunUpdateGenerator,
    ScannerBase,
    subprocess,
)


def _consume_updates(gen: RunUpdateGenerator):
    msgs = []
    result = None
    try:
        while msg := next(gen):
            msgs.append(msg)
    except StopIteration as st:
        result = st.value
    return result, msgs


@dataclass
class RunParam:
    stdout: str | list[str]
    returncode: int = 0
    stderr: str = ""
    as_json: bool = True


@pytest.fixture()
def patch_subprocess_run(request):
    with patch.object(subprocess, "run") as mock:
        completed_proc_mock = MagicMock(spec=subprocess.CompletedProcess)
        stdout = json.dumps(request.param.stdout) if request.param.as_json else request.param.stdout
        completed_proc_mock.stdout = stdout
        completed_proc_mock.returncode = request.param.returncode
        completed_proc_mock.stderr = request.param.stderr
        mock.return_value = completed_proc_mock

        yield mock, (request.param.stdout, request.param.returncode, request.param.stderr)


class TestRunProcess:
    @pytest.mark.parametrize("patch_subprocess_run", [RunParam({"success": True})], indirect=True)
    def test_stdout_is_the_result(self, patch_subprocess_run):
        mock, (expected_res, _, _) = patch_subprocess_run
        gen = ScannerBase.run(["do", "something"], parse_json=True, stream_process_output=False)
        result, messages = _consume_updates(gen)
        mock.assert_called()
        assert len(messages) == 0
        assert result == expected_res

    @pytest.mark.parametrize("patch_subprocess_run", [RunParam({"success": True})], indirect=True)
    def test_parse_result_as_json_by_default(self, patch_subprocess_run):
        mock, (expected_res, _, _) = patch_subprocess_run
        gen = ScannerBase.run(["do", "something"], stream_process_output=False)
        result, messages = _consume_updates(gen)
        mock.assert_called()
        assert len(messages) == 0
        assert result == expected_res

    @pytest.mark.parametrize("patch_subprocess_run", [RunParam("my expected response", as_json=False)], indirect=True)
    def test_non_json_result_can_be_forwarded_as_result(self, patch_subprocess_run):
        mock, (expected_res, _, _) = patch_subprocess_run
        gen = ScannerBase.run(["do", "something"], parse_json=False, stream_process_output=False)
        result, messages = _consume_updates(gen)
        mock.assert_called()
        assert len(messages) == 0
        assert result == expected_res

    @pytest.mark.parametrize(
        "patch_subprocess_run",
        [RunParam("something", stderr="invalid command", returncode=404, as_json=False)],
        indirect=True,
    )
    def test_stderr_is_forwarded_as_warning_update_if_it_has_result(self, patch_subprocess_run):
        mock, (expected_res, _, err_msg) = patch_subprocess_run
        gen = ScannerBase.run(["do", "something"], parse_json=False)
        result, messages = _consume_updates(gen)
        mock.assert_called()
        assert len(messages) == 1  # warning from tool + information regarding the warning to avoid confusion
        lvl, msg = messages[0]
        assert lvl == UpdateType.Warning
        assert err_msg in msg
        assert result is expected_res

    @pytest.mark.parametrize("patch_subprocess_run", [RunParam("{success:}", as_json=False)], indirect=True)
    def test_malformed_json_is_handled_as_error_update(self, patch_subprocess_run):
        mock, (_) = patch_subprocess_run
        gen = ScannerBase.run(["do", "something"], stream_process_output=False)
        result, messages = _consume_updates(gen)
        mock.assert_called()
        assert len(messages) == 1
        lvl, msg = messages[0]
        assert lvl == UpdateType.Error
        assert "Malformed JSON" in msg
        assert result is None

    def test_streaming_output_yields_updates_during_process_run(self, fp):
        cmd = ["do", "something"]
        expected_messages = ["first update", "second update", "final result"]

        fp.register(cmd, stdout=expected_messages)

        gen = ScannerBase.run(cmd, stream_process_output=True, parse_json=False)
        result, messages = _consume_updates(gen)
        assert fp.call_count(cmd) == 1
        assert len(messages) == len(expected_messages)
        lvls, msgs = zip(*messages)
        assert set(lvls) == {UpdateType.Info}
        assert expected_messages == list(msgs)
        # all messages are part of the final result
        assert all((m in result for m in msgs))
