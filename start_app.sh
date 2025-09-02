#!/bin/bash
# Script para iniciar a aplicação Streamlit
echo "" | streamlit run app.py --server.port=5000 --server.address=0.0.0.0 --server.headless=true