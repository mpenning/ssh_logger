# ssh_logger

Use Netflix's [`go-expect`](https://github.com/Netflix/go-expect) library to login to `route-views.routeviews.org` and grab the BGP bestpath for a route.

## Build the binary

- `go mod init ssh_logger`
- `go mod tidy`
- `go build -o ssh_logger main.go`

## SSH into route-views and log the SSH session

- `./ssh_logger`

## License and Copyright

- Apache 2.0 License
- Copyright David Michael Pennington, 2023
