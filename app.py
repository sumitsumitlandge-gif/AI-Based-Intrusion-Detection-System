
import streamlit as st
import pandas as pd
import joblib
import matplotlib.pyplot as plt

st.set_page_config(
    page_title="AI Intrusion Detection System",
    page_icon="🛡️",
    layout="wide"
)

st.title("🛡️ AI-Based Intrusion Detection System")
st.write(
    "Upload network traffic data in CSV, Excel, or JSON format "
    "to detect potentially malicious activity."
)


@st.cache_resource
def load_model():
    return joblib.load("intrusion_detection_model..joblib")


try:
    artifact = load_model()
    model = artifact["model"]
    feature_names = artifact["feature_names"]
    feature_medians = artifact["feature_medians"]
except Exception as e:
    st.error(f"Model could not be loaded: {e}")
    st.stop()


try:
    evaluation = joblib.load("intrusion_detection_evaluation.joblib")
except Exception as e:
    st.error(f"Evaluation metrics could not be loaded: {e}")
    st.stop()


uploaded_file = st.file_uploader(
    "Upload network traffic data (CSV, Excel, or JSON)",
    type=["csv", "xlsx", "xls", "json"]
)

if uploaded_file is not None:
    MAX_FILE_SIZE = 50 * 1024 * 1024
    MAX_ROWS = 100000

    if uploaded_file.size > MAX_FILE_SIZE:
        st.error("File is too large. Please upload a file under 50 MB.")
        st.stop()

    try:
        file_name = uploaded_file.name.lower()

        if file_name.endswith(".csv"):
            data = pd.read_csv(uploaded_file)

        elif file_name.endswith((".xlsx", ".xls")):
            data = pd.read_excel(uploaded_file)

        elif file_name.endswith(".json"):
            data = pd.read_json(uploaded_file)

        else:
            st.error("Unsupported file type. Upload CSV, Excel, or JSON.")
            st.stop()

        if data.empty:
            st.error("The uploaded file is empty.")
            st.stop()

        if len(data.columns) == 0:
            st.error("The uploaded file contains no columns.")
            st.stop()

        if len(data) > MAX_ROWS:
            st.error(
                f"The file contains {len(data):,} rows. "
                f"Please upload no more than {MAX_ROWS:,} rows."
            )
            st.stop()

        st.subheader("📄 Uploaded Dataset")
        st.write("Rows:", len(data))
        st.write("Columns:", len(data.columns))
        st.dataframe(data.head(10), use_container_width=True)

        if st.button("🔍 Analyze Network Traffic"):
            missing_features = [
                col for col in feature_names
                if col not in data.columns
            ]

            if missing_features:
                st.error(
                    f"This file is missing {len(missing_features)} required "
                    "features. Upload data containing the required "
                    "network traffic features."
                )
                st.write(
                    "First missing features:",
                    missing_features[:15]
                )

            else:
                X = data[feature_names].copy()

                # Convert features to numeric values
                for col in feature_names:
                    X[col] = pd.to_numeric(
                        X[col], errors="coerce"
                    )

                # Replace infinite values
                X = X.replace(
                    [float("inf"), -float("inf")],
                    float("nan")
                )

                # Count missing or invalid values
                invalid_count = int(X.isna().sum().sum())
                total_feature_values = X.shape[0] * X.shape[1]

                if total_feature_values > 0:
                    invalid_percentage = (
                        invalid_count / total_feature_values
                    ) * 100
                else:
                    invalid_percentage = 0

                if invalid_count > 0:
                    st.warning(
                        f"{invalid_count:,} missing or invalid feature "
                        f"values ({invalid_percentage:.4f}%) were found. "
                        "The model's training medians will be used "
                        "to replace them."
                    )

                # Fill missing values with training medians
                X = X.fillna(feature_medians)

                if X.isna().any().any():
                    st.error(
                        "Some features could not be cleaned. "
                        "Please check the uploaded data and model artifact."
                    )
                    st.stop()

                # Generate predictions
                predictions = model.predict(X)

                results = data.copy()
                results["AI_Prediction"] = predictions

                st.subheader("📊 Analysis Results")
                st.dataframe(results, use_container_width=True)

                st.subheader("📌 Prediction Summary")

                summary = (
                    pd.Series(predictions)
                    .value_counts()
                    .rename_axis("Predicted Category")
                    .reset_index(name="Number of Records")
                )

                st.dataframe(summary, use_container_width=True)

                suspicious = sum(
                    str(label).upper() != "BENIGN"
                    for label in predictions
                )

                metric_col1, metric_col2 = st.columns(2)

                metric_col1.metric(
                    "Total Records",
                    f"{len(predictions):,}"
                )
                metric_col2.metric(
                    "Predicted Non-BENIGN Records",
                    f"{suspicious:,}"
                )

                # Saved model evaluation
                st.subheader(
                    "🧪 Model Evaluation — Unseen Test Data"
                )

                metric1, metric2, metric3, metric4 = st.columns(4)

                metric1.metric(
                    "Accuracy",
                    f"{evaluation['accuracy']:.2%}"
                )
                metric2.metric(
                    "Weighted Precision",
                    f"{evaluation['precision_weighted']:.2%}"
                )
                metric3.metric(
                    "Weighted Recall",
                    f"{evaluation['recall_weighted']:.2%}"
                )
                metric4.metric(
                    "Weighted F1-score",
                    f"{evaluation['f1_weighted']:.2%}"
                )

                st.caption(
                    "These metrics describe the saved model's held-out "
                    "test evaluation, not its accuracy on the uploaded file."
                )

                # Confusion matrix
                st.subheader("📊 Confusion Matrix")

                labels = evaluation["labels"]

                cm = pd.DataFrame(
                    evaluation["confusion_matrix"],
                    index=labels,
                    columns=labels
                )

                st.write(
                    "Rows = actual categories; "
                    "columns = predicted categories."
                )
                st.dataframe(cm, use_container_width=True)

                # Traffic category distribution
                st.subheader("Traffic Category Distribution")

                category_counts = pd.Series(
                    predictions
                ).value_counts()

                total_predictions = category_counts.sum()

                chart_col, table_col = st.columns([1.3, 1])

                with chart_col:
                    fig, ax = plt.subplots(figsize=(6, 5))

                    ax.pie(
                        category_counts.values,
                        labels=None,
                        autopct=lambda p: (
                            f"{p:.1f}%" if p >= 3 else ""
                        ),
                        startangle=90,
                        pctdistance=0.7,
                        wedgeprops={
                            "edgecolor": "white",
                            "linewidth": 2
                        }
                    )

                    ax.axis("equal")
                    fig.tight_layout()

                    st.pyplot(fig, use_container_width=True)
                    plt.close(fig)

                with table_col:
                    st.subheader("Category Breakdown")

                    breakdown = pd.DataFrame({
                        "Category": category_counts.index,
                        "Records": category_counts.values,
                        "Share (%)": (
                            category_counts.values
                            / total_predictions * 100
                        ).round(2)
                    })

                    st.dataframe(
                        breakdown,
                        use_container_width=True,
                        hide_index=True
                    )

                # Overall verdict
                st.subheader("🛡️ Overall Traffic Security Verdict")

                if suspicious == 0:
                    st.success(
                        "🟢 No potentially malicious traffic was predicted. "
                        "All records were classified as BENIGN."
                    )
                else:
                    st.error(
                        f"🔴 Warning: potentially malicious traffic was "
                        f"predicted in {suspicious:,} out of "
                        f"{len(predictions):,} records."
                    )

                st.caption(
                    "This verdict is based on AI predictions, not confirmed "
                    "attack evidence. False positives and false negatives "
                    "are possible."
                )

                # Download results
                csv = results.to_csv(index=False).encode("utf-8")

                st.download_button(
                    "⬇️ Download Analysis Results",
                    data=csv,
                    file_name="intrusion_detection_results.csv",
                    mime="text/csv"
                )

                st.warning(
                    "This is a preliminary ML analysis, not a live network "
                    "monitor. Predictions can be wrong and should be reviewed."
                )

    except Exception as e:
        st.error(f"Could not analyze this file: {e}")
