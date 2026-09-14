FROM ghcr.io/zaproxy/zaproxy:stable

USER root
RUN mkdir -p /opt/aegis /tmp/aegis-zap \
    && chown -R zap:zap /opt/aegis /tmp/aegis-zap
COPY --chown=zap:zap worker.py /opt/aegis/worker.py

USER zap
WORKDIR /zap/wrk
ENV PYTHONUNBUFFERED=1
CMD ["python3", "/opt/aegis/worker.py"]
