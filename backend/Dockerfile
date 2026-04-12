FROM node:18-alpine
WORKDIR /usr/src/app
COPY package*.json ./
RUN apk add --no-cache python3 make g++
RUN npm install --omit=dev
COPY . .
EXPOSE 8080
CMD ["node", "server.js"]