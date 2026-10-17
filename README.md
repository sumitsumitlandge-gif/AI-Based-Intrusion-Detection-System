# 🛡️ AI-Based Intrusion Detection System

A machine learning-based application that analyzes uploaded network traffic records and classifies them as **BENIGN or potentially malicious** using a trained intrusion detection model.

The application provides a Streamlit interface for uploading datasets, reviewing predictions, visualizing traffic categories, and downloading analysis results.

## Features

- Upload network traffic datasets in CSV, Excel (`.xlsx`, `.xls`), and JSON formats.
- Validate required model features and report missing columns.
- Handle missing, invalid, and infinite feature values using saved training medians.
- Predict network traffic categories using a trained machine learning model.
- View individual predictions and category summaries.
- Visualize predicted traffic categories with a pie chart.
- View the saved model's evaluation metrics and confusion matrix.
- Download analysis results as a CSV file.
- Display a preliminary security verdict with warnings about prediction uncertainty.
- Apply basic upload limits for file size and number of records.

## Technologies Used

- Python
- Streamlit
- Pandas
- Scikit-learn
- Joblib
- Matplotlib
- Openpyxl and xlrd for Excel file support

## Project Files

- `app.py` — Streamlit web application.
- `intrusion_detection_model..joblib` — Trained model artifact, including the required feature information and training medians.
- `intrusion_detection_evaluation.joblib` — Saved model evaluation metrics and confusion matrix.
- `requirements.txt` — Python dependencies.
- `CICIDS2017_sample.csv` — Sample network traffic dataset used for testing.

## Installation and Setup

### 1. Install Python

Install a compatible Python version and ensure Python is available from your terminal.

### 2. Open the project folder

Open Command Prompt and navigate to the project directory:

```bash
cd AI_Intrusion_Detection
```

### 3. Install dependencies

```bash
python -m pip install -r requirements.txt
```

### 4. Run the application

```bash
python -m streamlit run app.py
```

### 5. Open the application

Open the local URL displayed in the terminal, usually:

`http://localhost:8501`

Ensure both model artifact files are present in the project folder.

## How to Use

1. Start the Streamlit application.
2. Upload a CSV, Excel, or JSON network traffic dataset.
3. Review the uploaded data preview.
4. Click **Analyze Network Traffic**.
5. Review predictions, category summaries, evaluation metrics, and visualizations.
6. Download the results as a CSV file.

The uploaded dataset must contain the model's required network traffic features with compatible column names and values.

## Model Evaluation

During development, the trained model achieved approximately **99.34% accuracy** on its held-out test split.

This result applies to that evaluation setup only. It does not guarantee equivalent performance on independent datasets or real-world network traffic. Duplicate records, class imbalance, data leakage, and differences between datasets may affect measured performance.

The evaluation metrics displayed by the application describe the saved test evaluation; they are not a measurement of accuracy on each uploaded file.

## Limitations and Responsible Use

- Predictions are not confirmed evidence of an attack.
- False positives and false negatives may occur.
- Missing values are imputed using saved training medians, which can affect predictions.
- The model requires the expected features and compatible data.
- The application analyzes uploaded files; it is **not a live network monitoring system**.
- Predictions should be reviewed before any security action is taken.

## Future Improvements

- Evaluate performance on independent network traffic datasets.
- Improve detection of underrepresented attack categories.
- Add explainability methods such as SHAP.
- Develop independent monitoring of model and alert-pipeline reliability.
- Explore live network monitoring in a controlled test environment.

## Disclaimer

This project is intended for educational and research purposes. It should not be used as the sole basis for security decisions.
