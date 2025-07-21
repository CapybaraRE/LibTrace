# -------------------------------------------------------------------------------
#
# Скрипт для IDA Pro для идентификации функций по байтовым сигнатурам из JSON-файла.
#
# Оригинальная идея: Lasha Khasaia (@_qaz_qaz)
# Переработка и модернизация: Gemini AI
# Версия: 2.1 - Исправлена совместимость с API IDA 9.0+
#
# Описание:
# Этот скрипт позволяет пользователям применять имена к функциям в базе данных IDA
# на основе байтовых сигнатур. Он использует современный API ida_bytes.find_bytes.
#
# -------------------------------------------------------------------------------

import json
import idaapi
import idautils
import ida_funcs
import ida_bytes
import ida_name
import ida_kernwin
# import ida_inf # <- УДАЛЕНО: Этот модуль устарел и больше не существует
import ida_search # Для флагов поиска

PLUGIN_NAME = "SigMatcher"
PLUGIN_VERSION = "2.1 Modern API (Fixed)"

def rename_function(ea, name, existing_names):
    """
    Переименовывает функцию, избегая дубликатов.
    """
    base_name = str(name)
    final_name = base_name
    
    i = 1
    while final_name in existing_names:
        final_name = f"{base_name}_{i}"
        i += 1
    
    current_name = ida_funcs.get_func_name(ea)
    if ida_name.set_name(ea, final_name, ida_name.SN_NOCHECK | ida_name.SN_NOWARN):
        ida_kernwin.msg(f"[{PLUGIN_NAME}] 0x{ea:X}: {current_name} -> {final_name}\n")
        existing_names.add(final_name)
        return True
    else:
        ida_kernwin.msg(f"[{PLUGIN_NAME}] Ошибка: не удалось установить имя {final_name} для 0x{ea:X}\n")
        return False

def main():
    """
    Основная функция скрипта.
    """
    ida_kernwin.msg(f"--- {PLUGIN_NAME} {PLUGIN_VERSION} запущен ---\n")

    json_path = ida_kernwin.ask_file(False, "*.json", "Выберите JSON файл с сигнатурами")
    if not json_path:
        ida_kernwin.msg(f"[{PLUGIN_NAME}] Операция отменена пользователем.\n")
        return

    try:
        with open(json_path, 'r', encoding='utf-8') as f:
            signatures_data = json.load(f)
    except Exception as e:
        ida_kernwin.msg(f"[{PLUGIN_NAME}] Ошибка при чтении или разборе файла: {e}\n")
        return

    sig_count = len(signatures_data)
    ida_kernwin.msg(f"[{PLUGIN_NAME}] Загружено {sig_count} сигнатур. Начинаем поиск...\n")

    renamed_count = 0
    # Собираем существующие имена один раз для быстрой проверки
    existing_names = {name for ea, name in idautils.Names()}
    # Множество для хранения адресов уже переименованных функций, чтобы не трогать их дважды
    renamed_functions_ea = set()

    # --- ИСПРАВЛЕНО: Используем современный API idaapi.inf ---
    # Устанавливаем границы поиска на всю программу
    search_start_ea = ida_ida.inf_get_min_ea()
    search_end_ea = ida_ida.inf_get_max_ea()

    ida_kernwin.show_wait_box(f"Поиск {sig_count} сигнатур...")

    # Основной цикл: итерируемся по каждой сигнатуре
    for i, (name, sig_str) in enumerate(signatures_data.items()):
        if (i % 100) == 0:
            if ida_kernwin.user_cancelled():
                ida_kernwin.msg(f"[{PLUGIN_NAME}] Операция отменена пользователем.\n")
                break
            ida_kernwin.replace_wait_box(f"Прогресс: {i}/{sig_count} ({name})")
        
        # Начинаем поиск всех вхождений текущей сигнатуры
        current_ea = search_start_ea
        while current_ea < search_end_ea:
            # Используем быструю нативную функцию поиска
            found_ea = ida_bytes.find_bytes(
                sig_str,
                current_ea,
                search_end_ea,
                flags=ida_search.SEARCH_DOWN | ida_search.SEARCH_NOSHOW
            )

            # Если больше ничего не найдено, переходим к следующей сигнатуре
            if found_ea == idaapi.BADADDR:
                break

            # --- Валидация: проверяем, что найденный адрес - это начало функции ---
            func = ida_funcs.get_func(found_ea)
            # Убеждаемся, что функция существует и ее начало совпадает с найденным адресом
            if func and func.start_ea == found_ea:
                # Проверяем, не переименовали ли мы эту функцию ранее другой сигнатурой
                if found_ea not in renamed_functions_ea:
                    if rename_function(found_ea, name, existing_names):
                        renamed_count += 1
                        renamed_functions_ea.add(found_ea)
            
            # Сдвигаем курсор для следующего поиска, чтобы не найти то же самое
            current_ea = found_ea + 1

    ida_kernwin.hide_wait_box()
    ida_kernwin.msg(f"--- {PLUGIN_NAME}: Готово! Переименовано {renamed_count} функций. ---\n")

if __name__ == "__main__":
    main()