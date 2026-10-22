"""Optional ML classifier (extra: agentguard[ml]). Returns a 0..1 injection score."""
from __future__ import annotations

from typing import Callable


def load_embedding_classifier(examples: list, threshold_scale: float = 1.0) -> Callable[[str], float]:
    """Similarity to known injection examples via sentence-transformers.

    Pass ``classifier=load_embedding_classifier([...])`` to ``Guard``. Probabilistic signal only.
    """
    try:
        from sentence_transformers import SentenceTransformer, util  # type: ignore
    except ImportError as e:  # pragma: no cover
        raise ImportError("install agentguard[ml] to use the classifier") from e
    model = SentenceTransformer("all-MiniLM-L6-v2")
    ref = model.encode(examples, convert_to_tensor=True, normalize_embeddings=True)

    def score(text: str) -> float:
        emb = model.encode(text, convert_to_tensor=True, normalize_embeddings=True)
        return float(max(0.0, util.cos_sim(emb, ref).max().item()) * threshold_scale)

    return score
