FROM alpine:3.13.4

WORKDIR /app

COPY dist/aws-alb-auth-debugger-linux-amd64 aws-alb-auth-debugger
RUN chmod 700 aws-alb-auth-debugger

EXPOSE 8080

ENTRYPOINT [ "./aws-alb-auth-debugger" ]
