#!/usr/bin/env python
# encoding: utf-8
"""
通用配置验证框架

提供统一的配置验证方法，消除各监控器中重复的验证逻辑。
支持声明式配置验证和统一的错误信息格式。

使用方式：
    from utils.config_validator import ConfigValidator
    
    ConfigValidator.validate_required(config, ["min_count", "show_errors_only"])
    ConfigValidator.validate_int(config.get("min_count"), "min_count", min_val=0)
    ConfigValidator.validate_bool(config.get("show_errors_only"), "show_errors_only")
"""

# 兼容性导入
try:
    from typing import Dict, Any, List, Optional, Union
except ImportError:
    from .py2_compat import Dict, Any, List, Optional, Union


class ConfigValidator(object):
    """
    通用配置验证器
    
    提供统一的配置验证方法，确保配置类型和值符合预期。
    所有验证方法在验证失败时抛出 ValueError。
    """

    @staticmethod
    def validate_required(config, required_fields):
        # type: (Dict[str, Any], List[str]) -> None
        """
        验证配置中是否包含所有必需字段
        
        Args:
            config: 配置字典
            required_fields: 必需字段列表
            
        Raises:
            ValueError: 缺少必需字段时抛出
        """
        if config is None:
            raise ValueError("配置不能为空")
        
        if not isinstance(config, dict):
            raise ValueError(
                "配置必须为字典类型，当前类型: {}".format(type(config).__name__)
            )
        
        missing_fields = []
        for field in required_fields:
            if field not in config or config[field] is None:
                missing_fields.append(field)
        
        if missing_fields:
            raise ValueError(
                "配置中缺少必需字段: {}".format(", ".join(missing_fields))
            )

    @staticmethod
    def validate_type(value, expected_type, field_name):
        # type: (Any, Union[type, tuple], str) -> None
        """
        验证字段类型
        
        Args:
            value: 字段值
            expected_type: 期望的类型或类型元组
            field_name: 字段名称（用于错误信息）
            
        Raises:
            ValueError: 类型不匹配时抛出
        """
        if not isinstance(value, expected_type):
            type_name = type(expected_type).__name__ if hasattr(expected_type, '__name__') else str(expected_type)
            raise ValueError(
                "{} 必须为 {} 类型，当前类型: {}".format(
                    field_name, type_name, type(value).__name__
                )
            )

    @staticmethod
    def validate_int(value, field_name, min_val=None, max_val=None):
        # type: (Any, str, Optional[int], Optional[int]) -> None
        """
        验证整数字段
        
        Args:
            value: 字段值
            field_name: 字段名称
            min_val: 最小值（可选）
            max_val: 最大值（可选）
            
        Raises:
            ValueError: 验证失败时抛出
        """
        ConfigValidator.validate_type(value, int, field_name)
        
        if min_val is not None and value < min_val:
            raise ValueError(
                "{} 必须大于等于 {}，当前值: {}".format(field_name, min_val, value)
            )
        
        if max_val is not None and value > max_val:
            raise ValueError(
                "{} 必须小于等于 {}，当前值: {}".format(field_name, max_val, value)
            )

    @staticmethod
    def validate_float(value, field_name, min_val=None, max_val=None):
        # type: (Any, str, Optional[float], Optional[float]) -> None
        """
        验证浮点数字段
        
        Args:
            value: 字段值
            field_name: 字段名称
            min_val: 最小值（可选）
            max_val: 最大值（可选）
            
        Raises:
            ValueError: 验证失败时抛出
        """
        ConfigValidator.validate_type(value, (int, float), field_name)
        
        if min_val is not None and value < min_val:
            raise ValueError(
                "{} 必须大于等于 {}，当前值: {}".format(field_name, min_val, value)
            )
        
        if max_val is not None and value > max_val:
            raise ValueError(
                "{} 必须小于等于 {}，当前值: {}".format(field_name, max_val, value)
            )

    @staticmethod
    def validate_bool(value, field_name):
        # type: (Any, str) -> None
        """
        验证布尔字段
        
        Args:
            value: 字段值
            field_name: 字段名称
            
        Raises:
            ValueError: 验证失败时抛出
        """
        ConfigValidator.validate_type(value, bool, field_name)

    @staticmethod
    def validate_string(value, field_name, min_length=None, max_length=None, allowed_values=None):
        # type: (Any, str, Optional[int], Optional[int], Optional[List[str]]) -> None
        """
        验证字符串字段
        
        Args:
            value: 字段值
            field_name: 字段名称
            min_length: 最小长度（可选）
            max_length: 最大长度（可选）
            allowed_values: 允许的值列表（可选）
            
        Raises:
            ValueError: 验证失败时抛出
        """
        ConfigValidator.validate_type(value, str, field_name)
        
        if min_length is not None and len(value) < min_length:
            raise ValueError(
                "{} 长度必须大于等于 {}，当前长度: {}".format(field_name, min_length, len(value))
            )
        
        if max_length is not None and len(value) > max_length:
            raise ValueError(
                "{} 长度必须小于等于 {}，当前长度: {}".format(field_name, max_length, len(value))
            )
        
        if allowed_values is not None and value not in allowed_values:
            raise ValueError(
                "{} 必须是 {} 之一，当前值: '{}'".format(
                    field_name, ", ".join(allowed_values), value
                )
            )

    @staticmethod
    def validate_list(value, field_name, min_length=None, max_length=None, item_type=None):
        # type: (Any, str, Optional[int], Optional[int], Optional[type]) -> None
        """
        验证列表字段
        
        Args:
            value: 字段值
            field_name: 字段名称
            min_length: 最小长度（可选）
            max_length: 最大长度（可选）
            item_type: 列表元素类型（可选）
            
        Raises:
            ValueError: 验证失败时抛出
        """
        ConfigValidator.validate_type(value, list, field_name)
        
        if min_length is not None and len(value) < min_length:
            raise ValueError(
                "{} 列表长度必须大于等于 {}，当前长度: {}".format(field_name, min_length, len(value))
            )
        
        if max_length is not None and len(value) > max_length:
            raise ValueError(
                "{} 列表长度必须小于等于 {}，当前长度: {}".format(field_name, max_length, len(value))
            )
        
        if item_type is not None:
            for i, item in enumerate(value):
                if not isinstance(item, item_type):
                    raise ValueError(
                        "{} 列表元素 [{}] 必须为 {} 类型，当前类型: {}".format(
                            field_name, i, item_type.__name__, type(item).__name__
                        )
                    )

    @staticmethod
    def validate_dict(value, field_name, required_keys=None, optional_keys=None):
        # type: (Any, str, Optional[List[str]], Optional[List[str]]) -> None
        """
        验证字典字段
        
        Args:
            value: 字段值
            field_name: 字段名称
            required_keys: 必需键列表（可选）
            optional_keys: 可选键列表（可选）
            
        Raises:
            ValueError: 验证失败时抛出
        """
        ConfigValidator.validate_type(value, dict, field_name)
        
        if required_keys is not None:
            missing_keys = [key for key in required_keys if key not in value]
            if missing_keys:
                raise ValueError(
                    "{} 字典中缺少必需键: {}".format(field_name, ", ".join(missing_keys))
                )

    @staticmethod
    def validate_dict_values(value, field_name, value_type):
        # type: (Dict[str, Any], str, type) -> None
        """
        验证字典所有值的类型
        
        Args:
            value: 字典值
            field_name: 字段名称
            value_type: 期望的值类型
            
        Raises:
            ValueError: 验证失败时抛出
        """
        for key, val in value.items():
            if not isinstance(val, value_type):
                raise ValueError(
                    "{} 字典中键 '{}' 的值必须为 {} 类型，当前类型: {}".format(
                        field_name, key, value_type.__name__, type(val).__name__
                    )
                )

    @staticmethod
    def validate_schema(config, schema):
        # type: (Dict[str, Any], Dict[str, Dict[str, Any]]) -> None
        """
        根据模式验证配置
        
        Args:
            config: 配置字典
            schema: 配置模式，格式为:
                {
                    "field_name": {
                        "type": int/float/bool/str/list/dict,
                        "required": True/False,
                        "min": min_value (可选，用于数值),
                        "max": max_value (可选，用于数值),
                        "allowed": [values] (可选，用于字符串),
                        "default": default_value (可选)
                    }
                }
                
        Raises:
            ValueError: 验证失败时抛出
        """
        for field_name, field_schema in schema.items():
            # 检查必需字段
            if field_schema.get("required", False):
                if field_name not in config or config[field_name] is None:
                    raise ValueError(
                        "配置中缺少必需字段: {}".format(field_name)
                    )
            
            # 如果字段不存在且不是必需的，跳过
            if field_name not in config:
                continue
            
            value = config[field_name]
            field_type = field_schema.get("type")
            
            # 类型验证
            if field_type is not None:
                ConfigValidator.validate_type(value, field_type, field_name)
            
            # 范围验证（数值类型）
            if field_type in (int, float):
                min_val = field_schema.get("min")
                max_val = field_schema.get("max")
                if min_val is not None or max_val is not None:
                    ConfigValidator.validate_float(value, field_name, min_val, max_val)
            
            # 允许值验证（字符串类型）
            allowed = field_schema.get("allowed")
            if allowed is not None and field_type == str:
                ConfigValidator.validate_string(value, field_name, allowed_values=allowed)
            
            # 列表验证
            if field_type == list:
                min_len = field_schema.get("min_length")
                max_len = field_schema.get("max_length")
                item_type = field_schema.get("item_type")
                ConfigValidator.validate_list(value, field_name, min_len, max_len, item_type)
            
            # 字典值类型验证
            if field_type == dict:
                value_type = field_schema.get("value_type")
                if value_type is not None:
                    ConfigValidator.validate_dict_values(value, field_name, value_type)

    @staticmethod
    def merge_with_defaults(config, defaults):
        # type: (Dict[str, Any], Dict[str, Any]) -> Dict[str, Any]
        """
        将配置与默认值合并
        
        Args:
            config: 用户配置
            defaults: 默认配置
            
        Returns:
            Dict[str, Any]: 合并后的配置
        """
        result = defaults.copy()
        if config:
            result.update(config)
        return result

    @staticmethod
    def extract_defaults_from_schema(schema):
        # type: (Dict[str, Dict[str, Any]]) -> Dict[str, Any]
        """
        从模式中提取默认值
        
        Args:
            schema: 配置模式
            
        Returns:
            Dict[str, Any]: 默认值字典
        """
        defaults = {}
        for field_name, field_schema in schema.items():
            if "default" in field_schema:
                defaults[field_name] = field_schema["default"]
        return defaults
