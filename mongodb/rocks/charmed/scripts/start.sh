#!/bin/bash

/usr/bin/setpriv --clear-groups --reuid mongodb --regid mongodb -- /usr/bin/mongod
