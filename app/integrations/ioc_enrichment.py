import logging
import os
from app.integrations.hybrid_analysis.client import search_by_hash as hybrid_search
from app.integrations.threatfox.client import search_threatfox_by_hash as threatfox_search
from app.integrations.malwarebazaar.client import search_malwarebazaar_by_hash as malwarebazaar_search

HYBRID_API_KEY = os.environ.get("HYBRID_ANALYSIS_API_KEY")
def enrich_ioc(md5_hash=None, sha256_hash=None):
    results = {}
    logger = logging.getLogger(__name__)

    logger.debug(f"Starting IOC enrichment for md5_hash={md5_hash}, sha256_hash={sha256_hash}")

    # Prefer SHA256 for Hybrid Analysis
    if HYBRID_API_KEY and sha256_hash:
        logger.debug("Querying Hybrid Analysis with SHA256")
        hybrid = hybrid_search(sha256_hash)
        if hybrid:
            logger.debug("Hybrid Analysis returned data")
            results['hybrid_analysis'] = hybrid
        else:
            logger.debug("Hybrid Analysis returned no data")

    if md5_hash:
        logger.debug("Querying ThreatFox and MalwareBazaar with MD5")
        threatfox = threatfox_search(md5_hash)
        if threatfox:
            logger.debug("ThreatFox returned data")
            results['threatfox'] = threatfox
        else:
            logger.debug("ThreatFox returned no data")

        malwarebazaar = malwarebazaar_search(md5_hash)
        if malwarebazaar:
            logger.debug("MalwareBazaar returned data")
            results['malwarebazaar'] = malwarebazaar
        else:
            logger.debug("MalwareBazaar returned no data")

    logger.debug(f"IOC enrichment results: {results}")
    return results
