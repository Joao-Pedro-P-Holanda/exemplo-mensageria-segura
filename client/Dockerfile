FROM node:alpine AS bundle-stage


COPY package*.json ./

RUN npm install

COPY . .

RUN npm run build

FROM nginx:alpine

# Copy the static files to nginx html directory
COPY --from=bundle-stage dist /usr/share/nginx/html/
# Copy nginx configuration
COPY nginx.conf /etc/nginx/conf.d/default.conf

EXPOSE 80

CMD ["nginx", "-g", "daemon off;"]
