# Onboarding a new tool to the Comparison

All tools which are supported by the comparison and analysis tool have a dedicated Python script within the `evaluation/scanner` folder. In the respective file everything which is needed to **parse and analyze the results**, and to **start a scan** is implemented.

All scripts within that folder are automatically loaded by the Kalm benchmark upon starting, if the file meets the requirements listed below.

In order to add a new tool to the comparision there must exist:
- a dedicated script
- **result file** which can be loaded and analyzed by the tool.


## Quick Start
A detailed explanation for every step can be found in the [dedicated section](#steps-to-add-a-new-scanner)

1) create a new script in the `evaluation/scanner` folder
2) in there create a `Scanner` class, which inherits `ScannerBase`
3) add relevant information about the tool
4) implement parser for the results
5) (optional) add custom scan functionality
6) (optional) override function to obtain tool version
    - only necessary, if scanning is supported


## Result file

The result file is expected to meet certain expectations for it to be handled correctly:
- the preferred file format is `JSON`. If `JSON` is not supported, it is treated as textfile
- the file name has the pattern `<tool_name>_<version>_<date of scan>.<format>`
    - the version and date in the file name allow the comparison of results across multiple versions/iterations


---
## Steps to add a new scanner

### 1. Create a script in the `evaluation/scanner` folder
The script can be named as you wish, as long as it's located in that folder and it is unique.
Ideally, it should be have the same name as the scanner itself.  


### 2. Create a class named `Scanner`
Currently, the class must be called `Scanner`, so it can be discovered by the Kalm Benchmark.

The class must inherit from `ScannerBase`, which is located in the file `scanner_evaluator.py` in the same directory. This base-class has several utility functions, which can be freely used within your class.


For example:
```python
from .scanner_evaluator import ScannerBase

class Scanner(ScannerBase)
    NAME = "..."  # a class variable (see next step)
    ...
```


### 3. Add comparison-relevant information as class variables

The overview page of the benchmark web-app gets most of the information from the comparison from a preset number of class variables.

<details>
    <summary>Explanation of each field</summary>

- `NAME`: the name of the scanner. This name is also used to invoke CLI commands
- `NOTES`: an optional list of notes, which will be displayed on the details page of this scanner
- `CI_MODE`: a boolean flag if a _CI-mode_ of some sort is supported. Usually, for most scanners this means aborting the scans if findings of a certain severity are found. The reason for the abortion is then reported via the `exit-code`
- `CUSTOM_CHECKS`: a boolean flag or a textual description if the scanner supports the addition of custom checks in some way. If it's a text, then it's implicitely assumed to support custom checks.
- `RUNS_OFFLINE`: a boolean flag if the scanner is self-sufficient and can run without a connection to an external server
- `IMAGE_URL`: a URL to the logo of the scanner, which will be shown in the comparison page
- `FORMATS`: a list of output formats supported by the scanner
    - From this list only `JSON` is used internally to infer the file format when saving scan results.

- `SCAN_CLUSTER_CMD`: the full command to start a cluster scan as if it were invoked via the commandline.  
    - if this command is specified, the benchmark assumes that cluster scans are supported
    - _Note: it's assumed, that the tool is installed locally and (pre-)configured when executing this command._
- `SCAN_MANIFESTS_CMD`: the partial command to start a scan of the benchmark manifests.
    - if this command is specified, the benchmark assumes that manifest scans are supported
    - **Important:** the path to the benchmark files is appended automatically at the end of the command. If the path needs to be specified using a CLI flag,  just specify the flag at the end of the command, without the path.
    - _Note: it's assumed, that the tool is installed locally and (pre-)configured when executing this command._
- `SCAN_PER_FILE`: an internal flag for the manifest scan. If true, then a dedicated scan will be started for each manifest in the benchmark. This is only necessary, if the scanner supports only the scan of individual files and not entire directories.
- `VERSION_CMD`: Optional[list] = None
</details>


#### `*_CMD` fields are special cases

The 3 `CMD` fields are optional and primarily for convenience and assume a default behaviour of the commands.
If the default behaviour of these commands does not meet your requirement, you can customize the behaviour by overriding the respective `scan_cluster`, `scan_manifests` or `get_version` functions.  
If either the `CMD` field or the respective function are specified, the benchmark assumes that this feature is supported by the scanner, which will also be shown in the comparison page.



### 4. Implement function to parse the results

The `JSON` format is supported by nearly all scanners and hence is used as the default format. However, there is no standard format for the results. That's why the parsing of the results has to be implemented specific to every scanner.

#### Input

The parsing is handled by the classmethod `parse_results`, which receives the input from the `load_results` function.
`load_results` loads the content of the file from the specified path. If the file has the `json` file extension, then the content will be parsed before passing it to `parse_results`. If custom logic is required to load the content of the file a custom version of `load_results` can be implemented as well.

#### Output

The function is expected to return a **list of `CheckResult`s**. `CheckResult` is a dataclass from the same file as `ScannerBase`.
Not all fields of `CheckResult` have to be populated by parsing the results. Some of values originate from the benchmark itself, which will be set later in the processing pipeline.

The only mandatory fields are:
- `scanner_check_id`: the `id` of the check as used by the scanner
- `got`: the verdict from the scanner. For normalized results this is an instance of the enum `CheckStatus` which is either `Alert` or `Pass`.
    - this enum is located in the same file as `ScannerBase` and `CheckResult`
- `checked_path`: the path(s) in the resources based on which the scanner determined the result
    - some checks check multiple paths to come to a conclusen. Thus, this can be either a string or a list of strings
    - _Note: for consistency, any array on the path is denoted by the `[]` suffix (as opposied to `[*]` seen in some cases)._


The other optional fields are:
- `obj_name`: the name of the scanned Kubernetes resource
- `scanner_check_name`: the human readable name of the check
- `severity`: the textual severity of the finding. This can also be a numeric value formatted as string.
- `kind`: the kind of Kubernetes resource that was scanned (e.g., `Pod`, etc.)
- `namespace`: the namespace in which the resource is located
- `details`: a detailed description of the finding or recommended remediation provided by the scanner
- `extra`: any additional information that can be useful when inspecting results in the analysis page


We know, hardly any scanner reports the `checked_path` and it is not trivial to provide this mapping. However, this information is **necessary to avoid (undetected) false positives**.

<details>
<summary>An example for illustrattion</summary>

- the benchmark expects an alert for a specific misconfiguration
- the scanner is not able to detect this misconfiguration
- however, the scanner raises a (false positive) alert, but on an unrelated field
- without the information on the `checked_path` this would lead to an incorrect "true positive", because the benchmark expects an alert and the tool actually raised an alert.
</details>



### 5. (Optional) Implement custom scanning functionality

In some cases the default workflow of executing a scan with the provided `SCAN_*_CMD` and returning the results is not applicable. Thus, it's possible to provided a custom implementation by overriding the respective `scan_cluster` or `scan_manifests` functions.
If both, a custom function and the respective `SCAN_*_CMD` are specified the function takes precedence. It's possible to use the `SCAN_*_CMD` from within the function as well.

`scan_cluster` and `scan_manifests` are nearly the same with the exception, that `scan_manifests` expects the path to a file as an argment wheras `scan_cluster` does not accept any arguments.
To provide a consistent interface for any updates of the scanning process these functions are actually [Generators](https://wiki.python.org/moin/Generators).
An updated yielded by the generator is a tuple of an `UpdateType` and the actual message. Using this it's possible to have a consistent interface providing updates/results to any UI!
This means, if possible **avoid using prints** and instead yield updates.  

For convenience the `run` classmethod of the _base class_ can be used to handle the execution of the actual command.
Additionally, an 'warning update' is generated, when the exit code of the execution is > 0.
This method can be configured with the following arguments:
- `parse_json`: a boolean flag, if the scan returns results formatted as JSON and if these should be parsed right away
- `stream_process_output`: some scanners provide progress updates while scanning. When this flag is set, the updates will be forwarded to the UI (both in the terminal or the webpage)


### 6. (Optional) implement custom version function
When a scan can be executed for the scanner the results will be stored with a predefined format, part of which is the version number of the scanner (see [Result file](#result-file)).
Ideally, the version number is retrieved directly from the scanner.

If the version command for the scanner returns the version number directly (or with a prefixed `v`) the `VERSION_CMD` can be used.
If additional information is printed alongside the version number this output has to be parsed again using a custom `get_version` function that returns the version number.
