from pathlib import Path

from loguru import logger


def get_scanner_result_file_paths(name: str, data_dir: str | None = "./data") -> list[str]:
    """Retrieve a list of paths to files in the data directory matching the tool name in some form

    :param name: the name of the tool which must appear in the filename
    :param data_dir: the directory which contains the evaluation results of the tools, defaults to "./data"
    :return: a list of paths to result files matching the specified tool name
    """
    files = [str(p) for p in Path(data_dir).glob(f"{name.lower()}*.*")]
    if len(files) == 0:
        logger.warning(f"No result files for '{name}' found, so no summary can be loaded")
        return []
    return files
