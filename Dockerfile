ARG branch=latest
FROM cccs/assemblyline-v4-service-base:$branch

# Set service to be run
ENV SERVICE_PATH pe.pe.PE

# Install python dependencies
COPY requirements.txt requirements.txt
RUN pip install --no-cache-dir --user --requirement requirements.txt && rm -rf ~/.cache/pip

# Copy service code
WORKDIR /opt/al_service
COPY . .

# Patch version in manifest
ARG version=4.2.0.dev1
USER root

# Always get the latest version of those files
ADD https://raw.githubusercontent.com/dishather/richprint/master/comp_id.txt /opt/al_service/pe/comp_id.txt
RUN chmod 664 /opt/al_service/pe/comp_id.txt

ADD https://bazaar.abuse.ch/export/csv/cscb/ /opt/al_service/pe/cscb.csv
RUN chmod 664 /opt/al_service/pe/cscb.csv

RUN sed -i -e "s/\$SERVICE_TAG/$version/g" service_manifest.yml

# Switch to assemblyline user
USER assemblyline
