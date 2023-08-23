FROM golang:1.21-alpine as builder

WORKDIR /src

COPY go.mod .
COPY go.sum .
RUN go mod download

ADD . .
RUN go build -o bin/codacy-trivy

FROM busybox

COPY --from=builder /src/bin /dist/bin
COPY docs/ /docs/

RUN adduser -u 2004 -D docker
RUN chown -R docker:docker /docs

CMD [ "/dist/bin/codacy-trivy" ]
