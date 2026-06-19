"""Engine registry. Order here is informational; the pipeline sorts by stage."""
from __future__ import annotations

from .adversary_simulation import AdversarySimulationEngine
from .ai_analyst import AIAnalystEngine
from .api_discovery import ApiDiscoveryEngine
from .api_relationship import ApiRelationshipEngine
from .asset_criticality import AssetCriticalityEngine
from .asset_discovery import AssetDiscoveryEngine
from .asset_validation import AssetValidationEngine
from .assessment_planner import AssessmentPlannerEngine
from .attack_path import AttackPathEngine
from .attack_surface_graph import AttackSurfaceGraphEngine
from .authentication_mapping import AuthenticationMappingEngine
from .base import Engine
from .configuration_assessment import ConfigurationAssessmentEngine
from .cve_intelligence import CVEIntelligenceEngine
from .deep_crawler import DeepCrawlerEngine
from .exposure_intelligence import ExposureIntelligenceEngine
from .extended_detectors import ExtendedDetectorEngine
from .finding_correlation import FindingCorrelationEngine
from .interface_intelligence import InterfaceIntelligenceEngine
from .javascript_intelligence import JavaScriptIntelligenceEngine
from .mitre_intelligence import MitreIntelligenceEngine
from .parameter_intelligence import ParameterIntelligenceEngine
from .reporting import ReportingEngine
from .risk_scoring import RiskScoringEngine
from .security_posture import SecurityPostureEngine
from .service_fingerprint import ServiceFingerprintEngine
from .technology_detection import TechnologyDetectionEngine
from .validation_orchestration import ValidationOrchestrationEngine
from .visual_attack_surface import VisualAttackSurfaceEngine
from .vulnerability_correlation import VulnerabilityCorrelationEngine


def all_engines() -> list[type[Engine]]:
    return [
        AssetDiscoveryEngine,            # 0
        AssetValidationEngine,           # 1
        ServiceFingerprintEngine,        # 2
        TechnologyDetectionEngine,       # 2
        DeepCrawlerEngine,               # 3
        JavaScriptIntelligenceEngine,    # 4
        ApiDiscoveryEngine,              # 4
        AuthenticationMappingEngine,     # 4
        ParameterIntelligenceEngine,     # 5
        AssessmentPlannerEngine,         # 6
        ConfigurationAssessmentEngine,   # 7
        CVEIntelligenceEngine,           # 7
        ExtendedDetectorEngine,          # 7
        ValidationOrchestrationEngine,   # 8
        VulnerabilityCorrelationEngine,  # 9
        FindingCorrelationEngine,        # 10
        AttackSurfaceGraphEngine,        # 11
        RiskScoringEngine,               # 12
        AttackPathEngine,                # 13
        MitreIntelligenceEngine,         # 14
        AssetCriticalityEngine,          # 15 (new)
        ExposureIntelligenceEngine,      # 15 (new)
        ApiRelationshipEngine,           # 15 (new)
        InterfaceIntelligenceEngine,     # 15 (new)
        SecurityPostureEngine,           # 16 (new)
        AdversarySimulationEngine,       # 16 (new)
        VisualAttackSurfaceEngine,       # 16 (new)
        AIAnalystEngine,                 # 17
        ReportingEngine,                 # 18
    ]
