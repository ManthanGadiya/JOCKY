FROM python:3.11-slim
WORKDIR /app
# WeasyPrint system deps (pango/cairo/gdk) for PDF generation
RUN apt-get update && apt-get install -y --no-install-recommends \
    libpango-1.0-0 libpangocairo-1.0-0 libgdk-pixbuf-2.0-0 libcairo2 \
    libpangoft2-1.0-0 libjpeg62-turbo libopenjp2-7 shared-mime-info \
    && rm -rf /var/lib/apt/lists/*
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt && pip install --no-cache-dir "pydyf==0.11.0"
COPY app app/
EXPOSE 8000
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
