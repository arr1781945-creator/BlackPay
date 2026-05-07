from dataclasses import dataclass
from typing import Optional

@dataclass(frozen=True)
class AlgorithmMeta:
    name: str
    category: str
    nist_level: int
    public_key_bytes: int
    secret_key_bytes: int
    ciphertext_bytes: int = 0
    shared_secret_bytes: int = 0
    signature_bytes: int = 0
    bsi_compliant: bool = False
    nist_standardised: bool = False
    status: str = "candidate"
    notes: str = ""

KEM_ALGORITHMS = {
    "ML-KEM-512":  AlgorithmMeta("ML-KEM-512",  "kem", 1, 800,  1632, 768,  32, 0, True, True,  "standardised"),
    "ML-KEM-768":  AlgorithmMeta("ML-KEM-768",  "kem", 3, 1184, 2400, 1088, 32, 0, True, True,  "standardised"),
    "ML-KEM-1024": AlgorithmMeta("ML-KEM-1024", "kem", 5, 1568, 3168, 1568, 32, 0, True, True,  "standardised"),
    "FrodoKEM-640-AES":  AlgorithmMeta("FrodoKEM-640-AES",  "kem", 1, 9616,  19888, 9720,  16, 0, True, False, "alternate"),
    "FrodoKEM-976-AES":  AlgorithmMeta("FrodoKEM-976-AES",  "kem", 3, 15632, 31296, 15744, 24, 0, True, False, "alternate"),
    "FrodoKEM-1344-AES": AlgorithmMeta("FrodoKEM-1344-AES", "kem", 5, 21520, 43088, 21632, 32, 0, True, False, "alternate"),
    "BIKE-L1": AlgorithmMeta("BIKE-L1", "kem", 1, 1541, 3113, 1573, 32, 0, False, False, "alternate"),
    "BIKE-L3": AlgorithmMeta("BIKE-L3", "kem", 3, 3083, 6275, 3115, 48, 0, False, False, "alternate"),
    "HQC-128": AlgorithmMeta("HQC-128", "kem", 1, 2249, 2289, 4481, 64, 0, False, False, "alternate"),
    "HQC-192": AlgorithmMeta("HQC-192", "kem", 3, 4522, 4562, 9026, 64, 0, False, False, "alternate"),
    "HQC-256": AlgorithmMeta("HQC-256", "kem", 5, 7245, 7285, 14469, 64, 0, False, False, "alternate"),
}

SIG_ALGORITHMS = {
    "ML-DSA-44": AlgorithmMeta("ML-DSA-44", "sig", 2, 1312, 2528, 0, 0, 2420, True, True,  "standardised"),
    "ML-DSA-65": AlgorithmMeta("ML-DSA-65", "sig", 3, 1952, 4032, 0, 0, 3309, True, True,  "standardised"),
    "ML-DSA-87": AlgorithmMeta("ML-DSA-87", "sig", 5, 2592, 4896, 0, 0, 4627, True, True,  "standardised"),
    "Falcon-512":  AlgorithmMeta("Falcon-512",  "sig", 1, 897,  1281, 0, 0, 666,  False, True, "standardised"),
    "Falcon-1024": AlgorithmMeta("Falcon-1024", "sig", 5, 1793, 2305, 0, 0, 1280, False, True, "standardised"),
    "SPHINCS+-SHA2-128f-simple": AlgorithmMeta("SPHINCS+-SHA2-128f-simple", "sig", 1, 32, 64, 0, 0, 17088, False, True, "standardised"),
    "SPHINCS+-SHA2-256f-simple": AlgorithmMeta("SPHINCS+-SHA2-256f-simple", "sig", 5, 64, 128, 0, 0, 49856, False, True, "standardised"),
    "MAYO-1": AlgorithmMeta("MAYO-1", "sig", 1, 1168, 24, 0, 0, 321, False, False, "candidate"),
    "MAYO-2": AlgorithmMeta("MAYO-2", "sig", 1, 5488, 24, 0, 0, 180, False, False, "candidate"),
    "MAYO-3": AlgorithmMeta("MAYO-3", "sig", 3, 2656, 32, 0, 0, 577, False, False, "candidate"),
    "MAYO-5": AlgorithmMeta("MAYO-5", "sig", 5, 5008, 40, 0, 0, 838, False, False, "candidate"),
}

DEFAULT_TENANT_PQC_CONFIG = {
    "kem": "ML-KEM-1024",
    "sig": "ML-DSA-65",
    "hybrid_kem_enabled": True,
    "hybrid_kem_context": "BlackPay-HybridKEM-v1",
    "bsi_compliance_required": False,
    "nist_compliance_required": True,
    "min_nist_level": 3,
}

BSI_TENANT_PQC_CONFIG = {
    "kem": "ML-KEM-1024",
    "sig": "ML-DSA-65",
    "hybrid_kem_enabled": True,
    "hybrid_kem_context": "BlackPay-HybridKEM-v1-BSI",
    "bsi_compliance_required": True,
    "nist_compliance_required": True,
    "min_nist_level": 3,
}

def get_bsi_compliant_kems():
    return [k for k, v in KEM_ALGORITHMS.items() if v.bsi_compliant]

def get_bsi_compliant_sigs():
    return [k for k, v in SIG_ALGORITHMS.items() if v.bsi_compliant]

def get_nist_standardised_kems():
    return [k for k, v in KEM_ALGORITHMS.items() if v.nist_standardised]

def get_nist_standardised_sigs():
    return [k for k, v in SIG_ALGORITHMS.items() if v.nist_standardised]

def validate_tenant_config(config):
    errors = []
    kem = config.get("kem")
    sig = config.get("sig")
    min_level = config.get("min_nist_level", 1)
    if kem not in KEM_ALGORITHMS:
        errors.append(f"Unknown KEM: {kem}")
    elif KEM_ALGORITHMS[kem].nist_level < min_level:
        errors.append(f"KEM {kem} below min NIST level {min_level}")
    if sig not in SIG_ALGORITHMS:
        errors.append(f"Unknown SIG: {sig}")
    elif SIG_ALGORITHMS[sig].nist_level < min_level:
        errors.append(f"SIG {sig} below min NIST level {min_level}")
    if config.get("bsi_compliance_required"):
        if kem and kem in KEM_ALGORITHMS and not KEM_ALGORITHMS[kem].bsi_compliant:
            errors.append(f"KEM {kem} not BSI compliant")
        if sig and sig in SIG_ALGORITHMS and not SIG_ALGORITHMS[sig].bsi_compliant:
            errors.append(f"SIG {sig} not BSI compliant")
    return (len(errors) == 0, errors)
