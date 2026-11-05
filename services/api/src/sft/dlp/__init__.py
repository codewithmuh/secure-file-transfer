"""Data loss prevention (ADR-0022): text extraction in sft.dlp.extract, detectors in sft.dlp.detect.

Both import only sft.core and nothing that reaches a database, the network or metrics.
"""
