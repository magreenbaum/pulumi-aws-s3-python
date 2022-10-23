# Complete Example

Note that use of this module is intended to create resources which will incur monetary charges on your AWS bill. Run `pulumi destroy` when you no longer need these resources.

In the root of this repo:
```
export $PYTHONPATH=$PWD/modules
```

In this directory:
```
poetry install
pulumi stack init
pulumi config set aws:region us-west-2
pulumi preview
pulumi up
```