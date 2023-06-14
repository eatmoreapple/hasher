## Hasher

django password hasher implementation for golang.

```python

# django model operation

User.objects.create_user(username='test', password='test')
```

```go
package main

import (
    "fmt"
    "github.com/eatmoreapple/hasher"
)

func main()  {
    fmt.Println(hasher.Verify("test", "hashed password from django")) // true, nil
}
```