#!/usr/bin/env bash

# 打包当前目录下的所有文件，排除指定目录和文件
env COPYFILE_DISABLE=1 tar -zcf ~/Downloads/ebpf-monitor-$(date +%Y%m%d).tar.gz \
  --exclude='package.sh' \
  --exclude='tests' \
  --exclude='.pki' \
  --exclude='.venv' \
  --exclude='.tasks' \
  --exclude='*.backup' \
  --exclude='.docs' \
  --exclude='.git' \
  --exclude='.gitignore' \
  --exclude='.idea' \
  --exclude='.pytest_cache' \
  --exclude='.stfolder' \
  --exclude='.stignore' \
  --exclude='.stversions' \
  --exclude='bin' \
  --exclude='ebpf.iml' \
  --exclude='include' \
  --exclude='lib' \
  --exclude='pyvenv.cfg' \
  --exclude='.DS_Store' \
  --exclude='._*' \
  --exclude='__pycache__' \
  --exclude='*.pyc' \
  --exclude='*.pyo' \
  --exclude='tools' \
  --exclude='presentation' \
  --exclude='output/*.csv' \
  --exclude='logs/*.log' \
  --exclude='logs/*.log.*' \
  --exclude='temp/*.pid' \
  --exclude='analysis/daily_data/*/*.csv' \
  --exclude='analysis/reports/*/*.txt' \
  --exclude='analysis/reports/*.md' \
  .
