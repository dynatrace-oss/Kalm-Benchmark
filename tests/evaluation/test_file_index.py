from kalm_benchmark.evaluation.file_index import FileIndex

file_content = """apiVersion: scheduling.k8s.io/v1
kind: PriorityClass
description: Default priority class for all pods
globalDefault: true
metadata:
  name: default-priority
preemptionPolicy: Never
value: 1000
---
apiVersion: v1
kind: Namespace
metadata:
  name: kalm-benchmark
---
apiVersion: v1
kind: ResourceQuota
metadata:
  name: kalm-benchmark
spec:
  hard:
    cpu: 30
    memory: 20Gi
    pods: 1000
""".splitlines(
    keepends=True
)


class TestFileIndexCreation:
    def test_create_file_index(self):
        idx = FileIndex(file_content)
        assert len(idx) == 3

    def test_access_indexed_object(self):
        idx = FileIndex(file_content)
        obj = idx[1]
        assert obj["kind"] == "Namespace"

    def test_access_last_indexed_object(self):
        idx = FileIndex(file_content)
        obj = idx[-1]
        assert obj["kind"] == "ResourceQuota"

    def test_access_indexed_object_by_line_number(self):
        idx = FileIndex(file_content)
        obj = idx.get_at_line(12)  # in the middle of an object
        assert obj["kind"] == "Namespace"

    def test_access_last_indexed_object_by_line_number(self):
        idx = FileIndex(file_content)
        obj = idx.get_at_line(len(file_content) - 1)
        assert obj["kind"] == "ResourceQuota"
