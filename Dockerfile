FROM node:18-alpine
WORKDIR /app
COPY . /app/
RUN adduser appuser;echo 'appuser:appuser' | chpasswd
RUN chown -R appuser /app
USER appuser
RUN npm ci
RUN npm run build
RUN ls -la
CMD npm run daemon