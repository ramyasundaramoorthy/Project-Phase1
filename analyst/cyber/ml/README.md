
# ML subsystem

## 1. Immediately runnable controlled dataset

Generate healthcare-app telemetry:

    python ml/generate_healthcare_dataset.py

Train/evaluate the models with the existing:

    python ml/train_models.py

## 2. Public network datasets

For a research-grade extension, obtain CIC-IDS2017 or UNSW-NB15 from the
official/research distribution and keep the downloaded dataset outside this
repository if large.

Then:

    python ml/prepare_public_dataset.py path\to\dataset.csv

The adapter maps common labels into the project's seven threat categories.
Unsupported labels are excluded and should be documented in the report.

## Evaluation

The adapter saves:
- ml/reports/classification_report.json
- ml/reports/confusion_matrix.json
- ml/models/model_metadata.json

Do not combine train and test data. Do not report synthetic-data metrics as
real-world security performance. Public network datasets should be described
as network telemetry, not healthcare telemetry.
