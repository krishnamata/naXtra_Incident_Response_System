# Base image
FROM python:3.10-slim

# Set work directory
WORKDIR /app

# Copy dependencies
COPY requirements.txt .

# Install dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy app code
COPY ./app /app 



# Set environment variables
ENV PYTHONUNBUFFERED=1

# Expose port (change if needed)
EXPOSE 5000

# Command to run the app (customize for your SOAR module)
CMD ["python", "main.py"]
