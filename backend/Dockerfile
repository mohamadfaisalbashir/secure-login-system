FROM node:18-alpine
WORKDIR /usr/src/app
COPY package*.json ./

# Install python, make, dan g++ untuk kebutuhan compile bcrypt / node-gyp
RUN apk add --no-cache python3 make g++

RUN npm install --omit=dev
COPY . .
EXPOSE 8080
CMD ["node", "server.js"]