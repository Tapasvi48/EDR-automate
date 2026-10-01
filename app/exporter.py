import io
import re
from datetime import datetime

from fastapi.responses import Response
from openpyxl import Workbook
from openpyxl.cell import WriteOnlyCell
from openpyxl.styles import Alignment, Font, PatternFill
from openpyxl.utils import get_column_letter

_ILLEGAL = re.compile(r"[\000-\010]|[\013-\014]|[\016-\037]")
HEAD_FONT = Font(bold=True, color="FFFFFF")
HEAD_FILL = PatternFill("solid", fgColor="1F3A5F")


def _clean(v):
    if isinstance(v, str):
        return _ILLEGAL.sub("", v)[:32000]
    return v


def xlsx_response(sheets, filename):
    """sheets: list of (title, columns[(key,label)], rows[dict]). Uses XlsxWriter (several times faster on 1-lakh-row
    exports); falls back to openpyxl when it is not installed."""
    if len(sheets) == 1 and len(sheets[0][2]) * max(1, len(sheets[0][1])) > CSV_CELLS:
        return _csv(sheets[0], filename)  # very large single list: CSV is ~20x faster to write and opens in Excel
    try:
        import xlsxwriter  # noqa: F401
    except ImportError:
        return _xlsx_openpyxl(sheets, filename)
    return _respond(_xlsx_fast(sheets), filename)


CSV_CELLS = 600_000  # e.g. 1 lakh rows x 6+ columns


def _csv(sheet, filename):
    import csv
    _, columns, rows = sheet
    out = io.StringIO()
    out.write("\ufeff")  # UTF-8 BOM so Excel reads non-ASCII text correctly
    w = csv.writer(out)
    w.writerow([lbl for _, lbl in columns])
    keys = [k for k, _ in columns]
    for r in rows:
        w.writerow(["" if r.get(k) is None else r.get(k) for k in keys])
    data = out.getvalue().encode("utf-8")
    stamp = datetime.now().strftime("%Y%m%d_%H%M")
    # one body, not a stream: streaming a BytesIO sends it line by line (1 lakh tiny chunks for a big file)
    return Response(data, media_type="text/csv; charset=utf-8",
                             headers={"Content-Disposition": f'attachment; filename="{filename}_{stamp}.csv"'})


def _xlsx_fast(sheets):
    import xlsxwriter
    buf = io.BytesIO()
    wb = xlsxwriter.Workbook(buf, {"constant_memory": True, "strings_to_numbers": False, "strings_to_formulas": False,
                                   "strings_to_urls": False, "nan_inf_to_errors": True})
    head = wb.add_format({"bold": True, "font_color": "#FFFFFF", "bg_color": "#1F3A5F", "valign": "vcenter"})
    used = set()
    for title, columns, rows in sheets:
        name = re.sub(r"[\[\]\*\?/\\:]", "_", title)[:31] or "Sheet"
        base, i = name, 2
        while name.lower() in used:  # sheet names must be unique
            name = f"{base[:28]}_{i}"
            i += 1
        used.add(name.lower())
        ws = wb.add_worksheet(name)
        for j, (k, lbl) in enumerate(columns):
            w = max(10, min(45, len(lbl) + 2))
            for rw in rows[:200]:
                w = max(w, min(45, len(str(rw.get(k) or "")) + 2))
            ws.set_column(j, j, w)
        ws.freeze_panes(1, 0)
        for j, (_, lbl) in enumerate(columns):
            ws.write_string(0, j, str(lbl), head)
        keys = [k for k, _ in columns]
        for i, r in enumerate(rows, start=1):  # constant_memory: rows must be written in order, which they are
            for j, k in enumerate(keys):
                v = r.get(k)
                if v is None or v == "":
                    continue
                if isinstance(v, bool):
                    ws.write_boolean(i, j, v)
                elif isinstance(v, (int, float)):
                    ws.write_number(i, j, v)
                else:
                    ws.write_string(i, j, _clean(str(v)))
        if rows and columns:
            ws.autofilter(0, 0, len(rows), len(columns) - 1)
    wb.close()
    buf.seek(0)
    return buf


def _respond(buf, filename):
    stamp = datetime.now().strftime("%Y%m%d_%H%M")
    fname = f"{filename}_{stamp}.xlsx"
    return Response(
        buf.getvalue(), media_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        headers={"Content-Disposition": f'attachment; filename="{fname}"'})


def _xlsx_openpyxl(sheets, filename):
    wb = Workbook(write_only=True)
    for title, columns, rows in sheets:
        ws = wb.create_sheet(title=re.sub(r"[\[\]\*\?/\\:]", "_", title)[:31] or "Sheet")
        widths = [max(10, min(45, len(lbl) + 2)) for _, lbl in columns]
        for i, rw in enumerate(rows[:200]):
            for j, (k, _) in enumerate(columns):
                widths[j] = max(widths[j], min(45, len(str(rw.get(k) or "")) + 2))
        for j, w in enumerate(widths):
            ws.column_dimensions[get_column_letter(j + 1)].width = w
        ws.freeze_panes = "A2"
        head = []
        for _, lbl in columns:
            cell = WriteOnlyCell(ws, value=lbl)
            cell.font, cell.fill = HEAD_FONT, HEAD_FILL
            cell.alignment = Alignment(vertical="center")
            head.append(cell)
        ws.append(head)
        for r in rows:
            ws.append([_clean(r.get(k)) for k, _ in columns])
        if rows:
            ws.auto_filter.ref = f"A1:{get_column_letter(len(columns))}{len(rows) + 1}"
    buf = io.BytesIO()
    wb.save(buf)
    buf.seek(0)
    stamp = datetime.now().strftime("%Y%m%d_%H%M")
    fname = f"{filename}_{stamp}.xlsx"
    return Response(
        buf.getvalue(), media_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        headers={"Content-Disposition": f'attachment; filename="{fname}"'})
