
# Go-Ecommerce-API

This is a simple ecommerce API built with Golang.

**Features**

- Authentication with mail or Google
- Users
- Products

**Planned Features**

- Shopping Cart
- ...

## Development

```
go get github.com/Lanseuo/go-ecommerce-api
go run cmd/go-ecommerce-api/main.go
```

## Deployment

```
docker build -t lanseuo/go-ecommerce-api .
docker run -it -p 8080:8080 --env-file=variables.env lanseuo/go-ecommerce-api
```

## Meta

Lucas Hild - [https://lucas-hild.de](https://lucas-hild.de)  
This project is licensed under the MIT License - see the LICENSE file for details