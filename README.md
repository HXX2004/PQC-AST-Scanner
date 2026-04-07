# ⚛️ PQC-AST-Scanner

### Post-Quantum Cryptography Migration Scanner

PQC-AST-Scanner 是一個 **跨語言靜態分析工具**，用於自動盤點原始碼中的 **密碼學資產 (Cryptographic Assets)**，並識別：

* 量子脆弱演算法 (Quantum-Vulnerable)
* 傳統弱密碼學
* 不安全加密模式
* 硬編碼密鑰
* 不安全亂數
* 錯誤的密碼學參數

工具使用 **AST (Abstract Syntax Tree) 語義分析**，能比單純字串搜尋更精確地分析程式碼中的密碼學使用方式。

此外，本專案提供 **互動式 Web UI、AI 助手、以及風險視覺化分析**，協助企業進行 **Post-Quantum Cryptography (PQC) 遷移盤點**。

---

# 📊 系統架構

```
                ┌─────────────────────┐
                │   Streamlit Web UI  │
                │     website.py      │
                └──────────┬──────────┘
                           │
                    Scan Request
                           │
                ┌──────────▼──────────┐
                │     Scanner Core    │
                │      scanner.py     │
                │   AST Static Scan   │
                └──────────┬──────────┘
                           │
             ┌─────────────┼─────────────┐
             │             │             │
        Python AST      Java AST        C AST
         (ast)         (javalang)     (pycparser)
             │
             ▼
      Cryptographic Findings
             │
   ┌─────────┴─────────┐
   │                   │
Plotly Visualization   AI Analysis
       │                   │
       ▼                   ▼
 Interactive Dashboard   Gemini Chat
```

---

# 🚀 主要功能

## 1️⃣ AST 靜態分析 (核心)

透過 **語法樹分析**精確偵測密碼學使用方式，例如：

| 檢測項目               | 說明          |
| ------------------ | ----------- |
| MD5 / SHA1         | 弱雜湊         |
| DES / 3DES         | 弱加密         |
| RSA                | 量子脆弱演算法     |
| ECC                | 量子脆弱        |
| AES ECB            | 不安全模式       |
| AES CBC 無 IV       | IV 缺失       |
| Hardcoded Key      | 硬編碼密鑰       |
| Hardcoded Password | 硬編碼密碼       |
| Weak RNG           | 使用 `random` |
| PBKDF2 iterations  | 迭代次數不足      |

---

## 2️⃣ PQC 遷移盤點

工具會自動判斷 **PQC 遷移狀態**：

| 狀態                   | 說明               |
| -------------------- | ---------------- |
| PQC_READY            | 已使用 PQC 演算法      |
| VULNERABLE (QUANTUM) | RSA / ECC        |
| VULNERABLE (CLASSIC) | MD5 / SHA1 / DES |
| SAFE                 | AES 等抗量子演算法      |
| CRITICAL_SECRET_LEAK | 硬編碼密鑰            |

---

## 3️⃣ 支援 PQC 演算法偵測

可識別：

| PQC Algorithm      | 說明               |
| ------------------ | ---------------- |
| ML-KEM (Kyber)     | PQC Key Exchange |
| ML-DSA (Dilithium) | PQC Signature    |

---

## 4️⃣ Web Dashboard

使用 **Streamlit** 提供互動式介面：

功能包含：

* 📂 多檔案掃描
* 📁 資料夾掃描
* 📊 風險統計圖
* 📋 掃描結果表
* 🤖 AI 分析助手

---

## 5️⃣ AI 安全顧問

整合 **Gemini AI**，可直接詢問：

例如：

```
哪些演算法需要優先遷移？
```

```
如何將 RSA 改為 PQC？
```

```
這個專案的主要風險是什麼？
```

AI 會根據掃描結果提供建議。

---

# 📊 風險視覺化

掃描結果會自動生成 **Plotly 圓餅圖**：

顯示：

* 弱加密
* PQC 遷移目標
* 硬編碼密鑰
* 安全資產

幫助快速評估整體安全狀況。

---

# 🧠 支援語言

| Language | Parser      |
| -------- | ----------- |
| Python   | `ast`       |
| Java     | `javalang`  |
| C        | `pycparser` |

---

# 🛠 安裝方式

建議使用 **Python 虛擬環境**

### 1️⃣ Clone 專案

```
git clone https://github.com/your-repo/PQC-AST-Scanner.git
cd PQC-AST-Scanner
```

---

### 2️⃣ 建立虛擬環境

Windows

```
python -m venv venv
venv\Scripts\activate
```

Mac / Linux

```
python3 -m venv venv
source venv/bin/activate
```

---

### 3️⃣ 安裝套件

```
pip install streamlit
pip install pandas
pip install plotly
pip install javalang
pip install pycparser
pip install google-generativeai
pip install numpy
```

---

# ▶️ 執行系統

啟動 Web UI：

```
streamlit run website.py
```

瀏覽器將自動開啟：

```
http://localhost:8501
```

---

# 📂 使用方式

## 方法 1：上傳檔案

1️⃣ 點擊 **Upload Files**

2️⃣ 上傳原始碼

3️⃣ 點擊 **開始掃描**

---

## 方法 2：掃描資料夾

輸入：

```
C:/Users/Project/src
```

點擊：

```
直接掃描該目錄
```

系統會自動：

* 遞迴掃描
* 分析所有程式碼
* 產生安全報告

---

# 📋 掃描結果

每個發現包含：

| 欄位            | 說明     |
| ------------- | ------ |
| RuleID        | 規則編號   |
| Type          | 問題類型   |
| Location      | 檔案位置   |
| CodeSnippet   | 程式碼片段  |
| Message       | 問題描述   |
| FixSuggestion | 修復建議   |
| PQC_Status    | PQC 狀態 |

---

# 🔐 偵測範例

弱 Hash：

```python
hashlib.md5(data)
```

偵測結果：

```
RuleID: B324
Type: WEAK_HASH_MD5
Fix: Replace with SHA256
```

---

AES ECB：

```python
AES.new(key, AES.MODE_ECB)
```

偵測：

```
RuleID: B413_AES_WEAK
```

---

硬編碼密鑰：

```python
api_key = "123456789ABCDEF"
```

偵測：

```
RuleID: B702_HARDCODED_KEY
```

---

# 📊 專案結構

```
PQC-AST-Scanner
│
├─ scanner.py
│   AST 掃描核心
│
├─ website.py
│   Streamlit Web UI
│
├─ README.md
│
└─ requirements.txt
```

---
