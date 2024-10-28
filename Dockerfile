# Start from a lightweight Python image
FROM python:3.9-slim

# Set the working directory to /app in the container
WORKDIR /app

# Copy the current directory contents into the container at /app
COPY . /app

# Install required dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Expose the port your Flask app runs on
EXPOSE 44444

# Set the command to run the Flask server
CMD ["python", "netninja_server.py"]
