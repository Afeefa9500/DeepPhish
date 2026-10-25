
# DeepPhish URL Guard 

## About the Project

DeepPhish URL Guard is a phishing URL detection project I built to explore how machine learning can be used to identify potentially malicious links. I wanted to create a tool that does more than simply classify a URL—it should also help users understand what makes a link suspicious.

I built the application using Python and Streamlit, with a Random Forest classifier trained on URL-derived features. I also added URL analysis, optional domain-intelligence checks, batch scanning, scan history, and model evaluation reports.

The goal is to make phishing URL analysis accessible while learning how machine learning can support cybersecurity.

## The Problem

Phishing attacks often use deceptive URLs to trick users into visiting fraudulent websites and sharing sensitive information, such as passwords and financial details.

It can be difficult to distinguish a legitimate URL from a suspicious one just by looking at it. Features such as misleading domain structures, unusual characters, suspicious keywords, and shortened links can make this even harder.

I built DeepPhish to provide an initial assessment of a URL using machine learning and URL-based indicators, helping users investigate suspicious links more systematically.

## What I Built

- **Machine learning-based detection:** Trained a Random Forest classifier using 50 features extracted from URLs.
- **URL feature extraction:** Analyzed URL length, hostname structure, IP-address usage, suspicious keywords, URL shorteners, and other characteristics.
- **Risk indicators:** Presented URL characteristics that may help explain why a link deserves further investigation.
- **Domain intelligence:** Added optional DNS, domain-registration (RDAP), and TLS certificate checks for additional context.
- **Batch scanning:** Enabled users to analyze multiple URLs in one run.
- **Scan history:** Used SQLite to store scan records locally.
- **Exportable results:** Added support for exporting scan results for further analysis.
- **Model evaluation:** Implemented random-split and hostname-separated evaluation, along with confusion matrices and classification metrics.
- **Error analysis:** Added reports of misclassified URLs and feature importance to help investigate model weaknesses.

## Tech Stack

 
 Language : Python 
 Frontend : Streamlit 
 Machine learning: scikit-learn, Random Forest 
 Data processing: pandas, NumPy 
 Model storage: joblib 
 Database: SQLite 
 Visualizations: Plotly 
 HTTP requests : Requests 

## How It Works

1. The user enters a URL or provides multiple URLs for batch scanning.
2. The application parses and normalizes the URL.
3. The feature extraction module converts URL characteristics into numerical features.
4. The trained Random Forest model predicts whether the URL resembles phishing or legitimate examples from the training dataset.
5. The application presents the prediction and available risk indicators.
6. Optional domain-intelligence checks provide additional information when available.
7. Scan history and analysis results can be stored locally or exported.

## Dataset and Model Training

I used a phishing URL dataset containing URL information and classification labels. The training script extracts the features used by the application and trains a Random Forest classifier.

The model is evaluated using two approaches:

- **Random split:** Evaluates performance on a held-out portion of the dataset.
- **Hostname-separated split:** Evaluates performance on hostnames excluded from the training partition.

I used accuracy, phishing precision, phishing recall, F1-score, and confusion matrices to evaluate the model. I also added error-analysis reports to identify false positives and false negatives.

In my current evaluation, the random split achieved approximately 89% accuracy, while the hostname-separated evaluation achieved approximately 86% accuracy. These results are specific to the supplied dataset and evaluation setup; they do not guarantee performance on new phishing attacks.

## Getting Started

### Prerequisites

- Python 3.10 or a compatible newer version
- pip
- VS Code or another Python development environment

### 1. Set Up the Environment

Clone or download the project and open its directory in a terminal.

Create a virtual environment:

```bash
python -m venv .venv
```

Activate it on Windows:

```bash
.venv\Scripts\Activate
```

On macOS or Linux:

```bash
source .venv/bin/activate
```

### 2. Install Dependencies

```bash
pip install -r requirements.txt
```

### 3. Check the Dataset

Make sure the dataset is available at:

```text
data/dataset_phishing.csv
```

The dataset must contain `url` and `status` columns.

### 4. Train the Model

```bash
python train.py
```

This generates or updates the trained model and evaluation files, including:

- `model.pkl`
- `model_metrics.json`
- `misclassified_random_split.csv`
- `misclassified_hostname_split.csv`
- `feature_importance.csv`

### 5. Run the Application

```bash
streamlit run app.py
```

Open the local URL displayed in the terminal to use DeepPhish.


Public URL:
https://deepphish-amkdaavpbj5mqybe3wbchm.streamlit.app/


## Challenges and Design Decisions

One of the challenges I encountered was ensuring that the features used during training matched those extracted when a user scanned a URL. I addressed this by using a shared feature-extraction module.

I also recognized that a random train-test split alone may not give a complete picture of how well the model handles unfamiliar hostnames. I therefore added hostname-separated evaluation to examine generalization more carefully.

I chose Streamlit to build the interface quickly and Python's scikit-learn library to train and evaluate the classifier. SQLite provides simple local persistence without requiring a separate database server.

I kept the analysis focused on URLs and optional domain checks rather than automatically opening suspicious webpages. This limits exposure to potentially harmful content, although it also means the application cannot fully inspect page behavior.

## Known Limitations

- The model's performance depends on the quality and coverage of the training dataset.
- The model can incorrectly flag legitimate URLs or miss phishing URLs.
- URL-based features alone cannot determine whether a website is genuinely malicious.
- The application does not comprehensively inspect webpage content, scripts, forms, or all redirect chains.
- DNS, RDAP, and TLS checks depend on internet connectivity and external service availability.
- A valid TLS certificate does not guarantee that a website is trustworthy.
- Hostname-separated evaluation is useful but does not replace testing on an independent, recently collected dataset.
- Scan history is stored locally in SQLite; the application is not designed as a production-scale, multi-user security platform.
- The model's prediction score is not a calibrated probability that a URL is malicious.

## Future Improvements

Some areas I would like to explore further include:

- Testing the model on a separate, recently collected dataset.
- Reducing false positives without increasing missed phishing URLs excessively.
- Comparing results with established phishing-detection services.
- Improving explanations of individual predictions.
- Expanding automated testing and security validation.

## License

No license has been specified yet. Add an appropriate license before distributing the project.
