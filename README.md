# pairwise-upload-polyglot

## 领域

安全

## 主题

上传多态文件

## 说明

魔数识别、重编码与不可执行隔离。

初始状态下 `security/upload_polyglot.py` 中所有函数抛出 `NotImplementedError`，测试全部失败。
修复实现后运行：

```bash
python -m pytest -q
```

期望全部通过。
