# AWS SRR Client

## Usage

```js
import { AwsSrpClient } from 'aws-srp-client';

const client = new AwsSrpClient('region', 'poolId', 'clientId');
const result = await client.AuthenticateUser('username', 'password');
if (result.Success) {
    const tokens = result.AuthenticationResult;
    //
} else {
    //
}
```