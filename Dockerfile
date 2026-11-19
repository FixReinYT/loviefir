FROM node:24-bookworm-slim
WORKDIR /app
COPY --chown=node:node server.mjs index.html ./
RUN mkdir data && chown node:node data
USER node
EXPOSE 8080
CMD ["node","server.mjs"]
