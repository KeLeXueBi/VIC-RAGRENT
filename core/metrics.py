import re
from loguru import logger

class Metrics:
    """
    Maintain running evaluation statistics for commit-level vulnerability detection.

    This class supports resuming interrupted experiments by loading previously
    saved counters from the result file.
    """

    def __init__(self, result_file: str):
        self.result_file = result_file
        self.TP = 0
        self.FP = 0
        self.TN = 0
        self.FN = 0
        self.total = 0
        self.cwe_correct = 0

        self._load_previous()

    def _load_previous(self):
        """
        Load previously saved metric counters so the experiment can resume
        from an earlier checkpoint.
        """
        try:
            with open(self.result_file, "r", encoding="utf-8") as f:
                for line in f:
                    if line.strip():  # 跳过空行
                        # 提取数值
                        values = [int(x) for x in re.findall(r"\d+", line)]
                        if len(values) >= 6:
                            self.TP, self.FP, self.TN, self.FN, self.total, self.cwe_correct = values
                        logger.info(f"Loaded TP: {self.TP}, FP: {self.FP}, TN: {self.TN}, FN: {self.FN}, Total: {self.total}, CWE Correct Count: {self.cwe_correct}.")
        except FileNotFoundError:
            logger.warning(f"Previous result file {self.result_file} not found. Starting from scratch.")
    
    def update(self, result: dict, ground_truth: int, true_cwe: str):
        """
        Update the running metrics using one prediction result.

        CWE correctness is counted only for true positive detections whose
        predicted CWE list contains the ground-truth CWE label.
        """
        self.total += 1
        detected = result["vuln_detected"]

        if detected and ground_truth:
            self.TP += 1
            logger.info("Detected correctly (TP)")
            if true_cwe in result.get("cwe_list", []):
                self.cwe_correct += 1
                logger.info(f"CWE {true_cwe} detected correctly")

        elif detected and not ground_truth:
            self.FP += 1
            logger.info("Detected incorrectly (FP)")

        elif not detected and not ground_truth:
            self.TN += 1
            logger.info("Detected correctly (TN)")

        else:
            self.FN += 1
            logger.info("Detected incorrectly (FN)")
        
    @property
    def accuracy(self):
        return (self.TP + self.TN) / self.total if self.total else 0

    @property
    def precision(self):
        return self.TP / (self.TP + self.FP) if (self.TP + self.FP) else 0

    @property
    def recall(self):
        return self.TP / (self.TP + self.FN) if (self.TP + self.FN) else 0

    @property
    def cwe_rate(self):
        """
        Compute the proportion of correctly predicted CWE labels over all
        ground-truth positive samples.
        """
        return self.cwe_correct / (self.TP + self.FN) if (self.TP + self.FN) else 0

    def log(self):
        # Print the current metric summary to the logger.
        logger.info(f"TP={self.TP}, FP={self.FP}, TN={self.TN}, FN={self.FN}, Total={self.total}")
        logger.info(f"Accuracy: {self.accuracy:.0%}")
        logger.info(f"Precision: {self.precision:.0%}")
        logger.info(f"Recall: {self.recall:.0%}")
        logger.info(f"CWE Accuracy: {self.cwe_rate:.0%}")

    def save(self):
        # Persist the current counters and derived metrics to the result file.
        with open(self.result_file, 'w', encoding='utf-8') as f:
            f.write(f"TP: {self.TP}, FP: {self.FP}, TN: {self.TN}, FN: {self.FN}, total: {self.total}, CWE_correct: {self.cwe_correct}\n")
            f.write(f"Accuracy: {self.accuracy:.0%}\n")
            f.write(f"Precision: {self.precision:.0%}\n")
            f.write(f"Recall: {self.recall:.0%}\n")
            f.write(f"CWE accuracy: {self.cwe_rate:.0%}\n")
