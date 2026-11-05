"""ML layer (owner: Asim).

The two context classifiers the scoring model uses, with the interfaces from
docs/cvss-mapping-contract.md (types in :mod:`app.core.contracts`):

* :func:`app.ml.sensitivity.classify` -- endpoint -> SensitivityClass
* :func:`app.ml.body_classifier.analyze` -- response -> set[BodySignal]

``body_classifier`` is Asim's detector; ``sensitivity`` puts a static-asset rule
and an optional anchor classifier (``config/sensitivity_anchors.yaml``) in front
of the built-in keyword classifier in ``app.core``. The contract test
(``tests/unit/test_ml_stubs.py``, renamed ``test_ml_contract.py`` on
``atta/p11-final-audit``) keeps both conforming.
"""
