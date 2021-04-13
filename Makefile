run:
	go run main.go

build-linux-amd64:
	GOOS=linux GOARCH=amd64 go build -o dist/aws-alb-auth-debugger-linux-amd64

dockerfile: build-linux-amd64
	docker build -t sklarsa/aws-alb-auth-debugger .
