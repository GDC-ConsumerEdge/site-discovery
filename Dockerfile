# Use an official Python runtime as a parent image
FROM python:3.11-slim

# Create a non-root user and group for security
RUN addgroup --system app && adduser --system --ingroup app app

# Set the working directory in the container
WORKDIR /app

# Copy the requirements file into the container
# and install dependencies. This is done first to leverage Docker layer caching.
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

# Copy the application code into the container
COPY . .

# Change the owner of the application files to the new user
RUN chown -R app:app /app

# Switch to the non-root user
USER app

# Set the entrypoint for the container.
# This allows you to pass arguments to your script from the `docker run` command.
ENTRYPOINT ["python", "main.py"]