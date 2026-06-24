FROM golang:1.22 AS build
WORKDIR /src
COPY . .
RUN CGO_ENABLED=0 go build -buildvcs=false -mod=vendor -o /cpcert .

FROM debian:11-slim
COPY --from=build /cpcert /usr/local/bin/cpcert
ENTRYPOINT ["cpcert"]
