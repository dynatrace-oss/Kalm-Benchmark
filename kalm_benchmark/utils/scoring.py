from enum import Enum

class CcssAccessVector(float, Enum):
    NETWORK = 1.0
    ADJACENT = 0.646
    LOCAL = 0.395

class CcssAuthentication(float, Enum):
    MULTIPLE = 0.45
    SINGLE = 0.56
    NONE = 0.704

class CcssAccessComplexity(float, Enum):
    HIGH = 0.35
    MEDIUM = 0.61
    LOW = 0.71

class CcssConfidentialityImpact(float, Enum):
    NONE = 0.0
    PARTIAL = 0.275
    COMPLETE = 0.66

class CcssIntegrityImpact(float, Enum):
    NONE = 0.0
    PARTIAL = 0.275
    COMPLETE = 0.66

class CcssAvailabilityImpact(float, Enum):
    NONE = 0.0
    PARTIAL = 0.275
    COMPLETE = 0.66

def ccss_severity_from_base_score(base_score: float = 0.0) -> str:
        """
        Determine the severity level based on the CCSS score.
        :return: Severity level as a string
        """
        if base_score == 0.0:
            return "None"
        elif base_score <= 3.9:
            return "Low"
        elif base_score <= 6.9:
            return "Medium"
        elif base_score <= 8.9:
            return "High"
        elif base_score <= 10.0:
            return "Critical"
        else:
            return "Unknown"
        
def ccss_score_calculator(access_vector: CcssAccessVector, authentication: CcssAuthentication, access_complexity: CcssAccessComplexity, 
                          confidentiality: CcssConfidentialityImpact, integrity: CcssIntegrityImpact, availability: CcssAvailabilityImpact) -> float:
    """
    Calculate the CCSS score based on the provided parameters.
    :param access_vector: Access Vector score
    :param authentication: Authentication score
    :param access_complexity: Access Complexity score
    :param confidentiality: Confidentiality Impact score
    :param integrity: Integrity Impact score
    :param availability: Availability Impact score
    :return: Calculated CCSS score
    """
    impact = 10.41*(1 - (1 - confidentiality) * (1 - integrity) * (1 - availability))

    if impact == 0:
        return 0.0

    f_impact = 1.176 if impact > 0 else 0
    exploitability = 20 * access_vector * authentication * access_complexity
    base_score = ((0.6 * impact) + (0.4 * exploitability) - 1.5) * f_impact

    return round(min(base_score, 10), 1)