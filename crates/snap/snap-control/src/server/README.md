# Control Plane API

## Testing with curl

The control plane API can be tested manually using curl. You need to have protoc
to be able to encode/decode the protobuf messages.

### List data planes

```sh
export CONTROL_PLANE_API=localhost:9002
export TOKEN=<SNAP_TOKEN_JWT>
export PROTO_PATH="./endhost/public/snap/snap-core/protobuf"

curl -s -X POST http://{$CONTROL_PLANE_API}/connectrpc.v1.control_plane/list_data_planes \
    -H "Content-Type: application/proto" \
    -H "Authorization: Bearer $TOKEN" |
    protoc --decode="snap.control_plane.experimental.ListDataPlanesResponse" --proto_path=$PROTO_PATH $PROTO_PATH/control_plane/experimental.proto < /dev/stdin
```

### Create Session

```sh

echo 'address: "DATAPLANE_ADDR"' | \
    protoc --proto_path=./endhost/sdk/proto \
    --encode=snap.control_plane.experimental.CreateSessionRequest \
    ./endhost/sdk/proto/control_plane/experimental.proto > /tmp/req.bin

curl -s -X POST http://{$CONTROL_PLANE_API}/connectrpc.v1.control_plane/create_session \
    -H "Content-Type: application/proto" \
    -H "Authorization: Bearer $TOKEN" \
    --data-binary @/tmp/req.bin |
    protoc --decode="snap.control_plane.experimental.CreateSessionResponse" --proto_path=$PROTO_PATH $PROTO_PATH/control_plane/experimental.proto < /dev/stdin
```
