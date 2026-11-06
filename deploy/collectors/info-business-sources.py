"""Readonly recovery business/operations readers. No external account actions."""
import datetime as dt
import json
import re
import sqlite3
import subprocess
import urllib.request
from collections import Counter
from decimal import Decimal
from pathlib import Path


def now():
    return dt.datetime.now(dt.timezone.utc).isoformat(timespec='seconds')


def metric(id, label, value, unit='', period='текущее состояние', source='', status=None, category='activity', latest=None, error=None):
    stamp = now()
    return dict(id=id, metric=id, label=label, value=value, unit=unit, period=period, source=source,
                generated_at=stamp, last_success=stamp if value is not None else None, source_latest_at=latest,
                error=error, status=status or ('ok' if value is not None else 'unknown'), category=category)


def table(id, title, columns, rows):
    return dict(id=id, title=title, columns=[dict(key=k, label=v, num=n) for k,v,n in columns], rows=rows)


def document(kpis, tables=None, charts=None, alerts=None):
    successes=[x['last_success'] for x in kpis if x.get('value') is not None and x.get('last_success')]
    return dict(generated_at=now(), last_success=max(successes) if successes else None, status='unknown' if not successes else 'partial' if any(x['status'] in ('unknown','partial','historical') for x in kpis) else 'ok', error=None,
                kpis=kpis, tables=tables or [], charts=charts or [], alerts=alerts or [])


def pg(database, sql):
    command=['docker','exec','-i','nana-wake-recovery-db','sh','-c','exec psql -X -qAt -v ON_ERROR_STOP=1 -U "$POSTGRES_USER" -d '+database]
    result=subprocess.run(command,input='BEGIN READ ONLY; SET LOCAL statement_timeout=5000; '+sql+' COMMIT;',text=True,capture_output=True,check=True,timeout=12)
    return json.loads(result.stdout)


def get(url):
    with urllib.request.urlopen(url,timeout=12) as response:
        return json.load(response)


def unknown_finance(source, period, noncommercial=False):
    labels=[('cash_receipts','Полученные оплаты'),('revenue','Заработанная выручка'),('expenses','Расходы'),('profit','Прибыль')]
    return [metric(id,label,None,'₽',period,source,status='not_applicable' if noncommercial else 'unknown',category='noncommercial' if noncommercial else id,error=None if noncommercial else 'Нет полного подтверждённого источника за период') for id,label in labels]


def audit_metric(data, id, label, key, unit='', category='activity'):
    observed=data['observed_at']
    period=(data['period_from']+' — '+data['period_to']) if 'period_from' in data else 'Google-аудит; данные изменены '+data['source_last_modified']
    item=metric(id,label,data[key],unit,period,data['source'],'historical',category,latest=data.get('source_last_modified',observed))
    item.update(generated_at=observed,last_success=observed)
    return item


def audit_table(data, id, title, rows):
    result=table(id,title,[('group','Группа',False),('count','Количество',True),('coverage','Период / смысл',False)],rows)
    result.update(source=data['source'],generated_at=data['observed_at'],last_success=data['observed_at'],source_latest_at=data.get('source_last_modified',data['observed_at']),status='historical',error=None,period='Фиксированный сохранённый аудит, не live источник')
    return result


def read_nanabanana():
    value=pg('nanabanana','''SELECT json_build_object('users',(SELECT count(*) FROM "User"),'latest',(SELECT max("createdAt") FROM "Generation"),'generations',(SELECT json_agg(x) FROM (SELECT status,count(*) AS count FROM "Generation" GROUP BY status) x),'payments',(SELECT json_agg(x) FROM (SELECT "paymentMethod"::text AS method,count(*) AS count,sum("amountRub")::text AS rub FROM "Transaction" WHERE type='PURCHASE' AND status='COMPLETED' GROUP BY "paymentMethod") x),'daily',(SELECT json_agg(x) FROM (SELECT ("createdAt" AT TIME ZONE 'UTC' AT TIME ZONE 'Asia/Vladivostok')::date::text AS day,count(*) AS count,count(*) FILTER(WHERE status='FAILED') AS failed FROM "Generation" GROUP BY 1 ORDER BY 1 DESC LIMIT 30) x));''')
    source='Nana PostgreSQL: копия 18.05.2026';period='историческая копия по '+str(value['latest'])+' UTC'
    kpis=unknown_finance(source,'текущий месяц / после копии 18.05.2026')
    kpis += [metric('users_snapshot','Пользователи в копии',value['users'],'чел',period,source,'historical',latest=value['latest']), metric('generations_snapshot','Генерации в копии',sum(x['count'] for x in value['generations']),'шт',period,source,'historical',latest=value['latest'])]
    for row in value['payments'] or []:
        kpis.append(metric('ledger_'+row['method'].lower(),'Покупки в учётной БД · '+row['method'],row['rub'],'₽',period,source,'historical','recorded_purchases',latest=value['latest'],error='Запись БД не подтверждает текущий cash или баланс'))
    kpis.append(metric('tokens_balance','Актуальные остатки токенов',None,'токены','после18.05.2026',source,error='Расходы после копии отсутствуют; платежи не равны балансу'))
    rows=sorted(value['daily'] or [],key=lambda x:x['day'])
    charts=[dict(id='generations_snapshot_daily',title='Генерации в исторической копии',kind='bar',unit='шт',note=period,series=[dict(name='Все',points=[[x['day'],x['count']] for x in rows]),dict(name='Ошибки',points=[[x['day'],x['failed']] for x in rows])])]
    audit=json.loads(Path('/opt/info-collectors/audit-aggregates/nana-audit-safe.json').read_text())
    additions=[audit_metric(audit,'audit_gross_captured','Подтверждённые поступления проверенного магазина в периоде аудита','gross_captured_rub','₽','cash_receipts'),audit_metric(audit,'audit_paid_count','Подтверждённые paid non-test платежи в периоде аудита','succeeded_paid_non_test','шт'),audit_metric(audit,'audit_money_refunds','Денежные возвраты в проверенном окне аудита','refunds_in_verified_window_rub','₽','refunds')]
    kpis=additions+kpis
    audit_rows=[dict(group='Отсутствуют в майской копии: подтверждённые поступления',count=audit['missing_from_may'],coverage='Окно аудита 18.05 — 04.11 00:11 UTC; один merchant'),dict(group='Из них: точная привязка к профилю May',count=audit['exact_may_profile_payments'],coverage='Подмножество 109 платежей, не остаток'),dict(group='Из них: внешний ID есть, профиля нет в May',count=audit['external_reference_profile_missing_in_may_payments'],coverage='Подмножество 109; May absence не означает отсутствие сейчас'),dict(group='Исторические конфликты владельца / metadata',count=audit['metadata_conflicts'],coverage='Старые записи May; не дополнительный cash'),dict(group='Исторические HTTP404, cash неизвестен',count=audit['provider_404_unknown'],coverage='Старые записи May; не unpaid/не ноль')]
    audit_summary=audit_table(audit,'yookassa_audit_scope','Сохранённый аудит ЮKassa: gross captured, не выручка/settlement/баланс',audit_rows)
    return document(kpis,[audit_summary,table('generation_statuses','Состояния генераций в копии',[('status','Статус',False),('count','Записей',True)],value['generations']),table('recorded_purchases','Покупки, записанные в копии; не текущая выручка',[('method','Способ',False),('count','Записей',True),('rub','Учтено ₽',False)],value['payments'] or [])],charts)


def read_wakeparty():
    values=pg('wakeparty','''SELECT json_build_object('gifts',(SELECT count(*) FROM "GiftCard"),'bookings',(SELECT count(*) FROM "PendingBooking"),'crm_bookings',(SELECT count(*) FROM "CrmBooking"),'crm_customers',(SELECT count(*) FROM "CrmCustomer"));''')
    services=get('http://127.0.0.1:8030/api/services')
    if isinstance(services,dict):services=services.get('services',services.get('data',[]))
    kpis=unknown_finance('Новая WakeDB / неполная история BookNow','текущий месяц / последние30дней')
    kpis += [metric('booknow_services','Доступные услуги BookNow',len(services),'шт',source='BookNow readonly /api/services'),metric('paid_bookings','Оплаченные брони за30дней',None,'шт','30дней','История ещё не восстановлена'),metric('gift_remaining','Реальные остатки сертификатов',None,'₽','настоящее время','Отдельный forensic audit; текущая БД не является production')]
    rows=[dict(entity=k,records=v,coverage='Новая БД, не история бизнеса') for k,v in values.items()]
    audit=json.loads(Path('/opt/info-collectors/audit-aggregates/wake-audit-safe.json').read_text())
    additions=[audit_metric(audit,'google_certificates','Уникальные сертификаты WAKE в Google-аудите','unique_certificates','шт'),audit_metric(audit,'google_face_value','Сумма номиналов Google-аудита: НЕ выручка и НЕ остаток','face_value_rub','₽','face_value'),audit_metric(audit,'google_refund_indicated','С отметкой возврата в Google','refund_indicated','шт'),audit_metric(audit,'google_usage_indicated','С отметкой использования в Google','usage_indicated','шт'),audit_metric(audit,'google_unmarked','Без отметки: НЕ статус «неиспользован»','unmarked_not_unused','шт'),audit_metric(audit,'google_imported','Импортировано в production GiftCard','imported','шт')]
    kpis=additions+kpis
    audit_rows=[dict(group='Уникальные WAKE в Google',count=audit['unique_certificates'],coverage='Аудит таблицы, не production GiftCard'),dict(group='Есть отметка возврата',count=audit['refund_indicated'],coverage='Google indication; деньги у провайдера не подтверждены'),dict(group='Есть отметка использования',count=audit['usage_indicated'],coverage='Google indication; remaining неизвестен'),dict(group='Нет отметки',count=audit['unmarked_not_unused'],coverage='Не означает unused'),dict(group='Импортировано в GiftCard',count=audit['imported'],coverage='Импорт не выполнялся; cash/remaining неизвестны')]
    audit_summary=audit_table(audit,'google_certificate_audit','Google-аудит сертификатов: cash и remaining неизвестны',audit_rows)
    return document(kpis,[audit_summary,table('recovery_db','Технические записи новой БД',[('entity','Таблица',False),('records','Записей',True),('coverage','Ограничение',False)],rows)])


BONDS_ADDITIONAL_OWNER_USERNAME = "nelson"


def _append_named_bonds_owner(doc, username):
    """Append one explicitly configured account; never replace legacy owner KPIs."""
    source = "SQLite: аккаунт Nelson; сохранённые данные, без свежей брокерской сверки"
    extra_kpis, extra_tables, extra_charts = [], [], []
    db = sqlite3.connect('file:/opt/bonds-recovery/data/portfolio.db?mode=ro',
                         uri=True, timeout=2)
    db.row_factory = sqlite3.Row
    try:
        db.execute("PRAGMA query_only=ON")
        matches = db.execute(
            "SELECT id FROM users WHERE lower(username)=lower(?)", (username,)
        ).fetchall()
        if not username or len(matches) != 1:
            extra_kpis.append(metric(
                "nelson_owner", "Nelson: источник данных", None, source=source,
                error="Настроенный аккаунт не найден или найден неоднозначно"))
        else:
            owner_id = matches[0]["id"]
            total = db.execute(
                "SELECT count(*) FROM portfolios WHERE user_id=?", (owner_id,)
            ).fetchone()[0]
            items = db.execute(
                "SELECT count(*) FROM portfolio_items i JOIN portfolios p "
                "ON p.id=i.portfolio_id WHERE p.user_id=? AND i.deleted_at IS NULL",
                (owner_id,)
            ).fetchone()[0]
            rows = [dict(r) for r in db.execute(
                "SELECT s.snapshot_date AS day,round(sum(s.total_value),2) AS value,"
                "round(sum(s.total_cost),2) AS cost,count(DISTINCT p.id) AS portfolios "
                "FROM portfolio_snapshots s JOIN portfolios p ON p.id=s.portfolio_id "
                "WHERE p.user_id=? GROUP BY s.snapshot_date "
                "ORDER BY s.snapshot_date DESC LIMIT 30", (owner_id,)
            )]
            rows.reverse()
            latest = rows[-1] if rows else {}
            covered = latest.get("portfolios", 0)
            period = "сохранённая запись " + str(latest.get("day", "отсутствует"))
            incomplete = ("Нет сохранённых снимков" if not rows else
                          "Последний снимок охватывает не все портфели аккаунта"
                          if covered != total else None)
            extra_kpis.extend([
                metric("nelson_portfolios", "Nelson: портфели", total, "шт", source=source),
                metric("nelson_portfolio_items", "Nelson: активные позиции", items, "шт", source=source),
                metric("nelson_snapshot_portfolios", "Nelson: портфели в последнем снимке",
                       covered if rows else None, "шт", period, source,
                       status="partial" if incomplete else "historical",
                       latest=latest.get("day"), error=incomplete),
                metric("nelson_portfolio_value_snapshot", "Nelson: оценка в сохранённом снимке",
                       latest.get("value"), "₽", period, source,
                       status="unknown" if not rows else "partial" if incomplete else "historical",
                       category="valuation", latest=latest.get("day"), error=incomplete),
                metric("nelson_purchase_cost_snapshot", "Nelson: стоимость покупки в снимке",
                       latest.get("cost"), "₽", period, source,
                       status="unknown" if not rows else "partial" if incomplete else "historical",
                       category="purchase_cost", latest=latest.get("day"), error=incomplete),
            ])
            extra_tables.append(table(
                "nelson_portfolio_history", "Nelson: сохранённые снимки; полнота истории не подтверждена",
                [("day", "Дата", False), ("value", "Оценка ₽", True),
                 ("cost", "Покупка ₽", True), ("portfolios", "Портфелей в снимке", True)], rows))
            extra_charts.append(dict(
                id="nelson_portfolio_snapshot_history", title="Nelson: история сохранённых снимков",
                kind="line", unit="₽", note=source,
                series=[dict(name="Оценка", points=[[r["day"], r["value"]] for r in rows]),
                        dict(name="Стоимость покупки", points=[[r["day"], r["cost"]] for r in rows])]))
    finally:
        db.close()
    return document(doc["kpis"] + extra_kpis, doc["tables"] + extra_tables,
                    doc["charts"] + extra_charts, doc.get("alerts", []))


def read_bonds():
    db=sqlite3.connect('file:/opt/bonds-recovery/data/portfolio.db?mode=ro',uri=True);db.row_factory=sqlite3.Row
    rows=[dict(x) for x in db.execute("SELECT s.snapshot_date AS day,round(sum(s.total_value),2) AS value,round(sum(s.total_cost),2) AS cost,count(*) AS portfolios FROM portfolio_snapshots s JOIN portfolios p ON p.id=s.portfolio_id WHERE p.user_id=1 AND s.snapshot_date<='2026-10-29' GROUP BY s.snapshot_date ORDER BY s.snapshot_date DESC LIMIT 30")];rows.reverse()
    coupons=db.execute('SELECT sum(c.coupons_total),max(c.updated_at),count(*) FROM tbank_coupons c JOIN portfolios p ON p.id=c.portfolio_id WHERE p.user_id=1').fetchone()
    counts={t:db.execute('SELECT count(*) FROM '+t).fetchone()[0] for t in ['users','portfolios','portfolio_items']};db.close()
    source='SQLite owner portfolio; восстановленная копия29.10.2026';latest=rows[-1] if rows else {};period='по сохранённой записи '+str(latest.get('day','дата неизвестна'))
    kpis=[metric('portfolio_value_snapshot','Оценка портфеля в копии',latest.get('value'),'₽',period,source,'historical','valuation',latest=latest.get('day')),metric('purchase_cost_snapshot','Стоимость покупки в записи',latest.get('cost'),'₽',period,source,'historical','purchase_cost',latest=latest.get('day')),metric('coupons_cached','Купоны накопительно в кэше',coupons[0],'₽','накопительно по '+str(coupons[1]),'tbank_coupons: частичный кэш','partial','coupons_received',latest=coupons[1],error='Нет полного журнала выплат по месяцам и свежей брокерской сверки')]
    kpis += unknown_finance('pro_payments пуст в восстановленной БД; текущие оплаты не подтверждены','текущий месяц / последние30дней')
    kpis.append(metric('current_market_value','Текущая рыночная стоимость',None,'₽','сейчас',source,error='price_snapshots пуст; синхронизация брокера выключена'))
    kpis += [metric(t,label,v,'шт','текущая восстановленная БД',source) for (t,v),label in zip(counts.items(),['Пользователи сервиса','Портфели сервиса','Позиции сервиса'])]
    charts=[dict(id='portfolio_snapshot_history',title='Историческая оценка портфеля; не текущая выручка',kind='line',unit='₽',note=source,series=[dict(name='Оценка',points=[[x['day'],x['value']] for x in rows]),dict(name='Стоимость покупки',points=[[x['day'],x['cost']] for x in rows])])]
    return _append_named_bonds_owner(document(kpis,[table('portfolio_history','Записи оценки портфеля владельца',[('day','Дата',False),('value','Оценка ₽',True),('cost','Покупка ₽',True),('portfolios','Портфелей в записи',True)],rows)],charts), BONDS_ADDITIONAL_OWNER_USERNAME)


def read_cars():
    rates=get('http://127.0.0.1:8050/api/cbr');content=get('http://127.0.0.1:8050/api/content')
    kpis=[metric('visitors_30d','Посетители за30дней',None,'чел','30дней','Общий nginx log не содержит vhost',error='Нельзя достоверно отделить Cars от других проектов'),metric('calc_30d','Расчёты за30дней',None,'шт','30дней','Локальные расчёты браузера; полноценного журнала нет'),metric('leads_30d','Заявки за30дней',None,'шт','30дней','CRM/журнал заявок не найден')]
    kpis+=unknown_finance('Cars: нет подтверждённого платёжного/расходного регистра','30дней')
    kpis += [metric('cbr_live','Живой курс ЦБ','да' if rates.get('live') and not rates.get('stale') else 'нет','','сейчас','GET /api/cbr',status='ok' if rates.get('live') else 'stale'),metric('content_fields','Разделов контента',len(content),'шт',source='GET /api/content')]
    rows=[dict(file=p.name,bytes=p.stat().st_size) for p in Path('/opt/cars-recovery/data').glob('*.json')]
    return document(kpis,[table('local_references','Восстановленные локальные справочники; production volume не найден',[('file','Файл',False),('bytes','Байт',True)],rows)])


def read_globalauto():
    php=r'''function val($n){$v=getenv($n);if($v!==false&&$v!=='')return $v;$f=getenv($n.'_FILE');return $f?trim(file_get_contents($f)):'';}$host=explode(':',val('WORDPRESS_DB_HOST'))[0];$db=new mysqli($host,val('WORDPRESS_DB_USER'),val('WORDPRESS_DB_PASSWORD'),val('WORDPRESS_DB_NAME'));$db->query('START TRANSACTION READ ONLY');$a=[];foreach(['types'=>"SELECT post_type AS type,post_status AS status,count(*) AS count,max(post_modified_gmt) AS latest FROM wp_posts GROUP BY post_type,post_status",'leads'=>"SELECT DATE(post_date_gmt) AS day,count(*) AS count FROM wp_posts WHERE post_type='submissions' AND post_status='publish' GROUP BY DATE(post_date_gmt) ORDER BY day DESC LIMIT30"] as $k=>$q){$r=$db->query(str_replace('LIMIT30','LIMIT 30',$q));$a[$k]=$r->fetch_all(MYSQLI_ASSOC);}$db->rollback();echo json_encode($a);'''
    r=subprocess.run(['docker','exec','globalauto-php-1','php','-r',php],capture_output=True,text=True,check=True,timeout=15);data=json.loads(r.stdout)
    counts={x['type']:int(x['count']) for x in data['types'] if x['status']=='publish'};source='WordPress wp_posts readonly; копия по01.11.2026'
    kpis=[metric('leads_snapshot','Заявки в WordPress, не продажи',counts.get('submissions'),'шт','историческая копия по01.11.2026',source,'historical'),metric('articles_snapshot','Опубликованные статьи',counts.get('articles'),'шт','копия по01.11.2026',source,'historical'),metric('pages_snapshot','Страницы',counts.get('page'),'шт','копия по01.11.2026',source,'historical')]+unknown_finance('Нет подтверждённого журнала оплат/расходов GlobalAuto','текущий месяц')
    rows=sorted(data['leads'],key=lambda x:x['day']);charts=[dict(id='saved_submissions',title='Сохранённые заявки по дате; не продажи',kind='bar',unit='шт',series=[dict(name='Заявки в копии',points=[[x['day'],int(x['count'])] for x in rows])])]
    return document(kpis,[table('post_types','Состав восстановленной БД WP',[('type','Тип',False),('status','Статус',False),('count','Записей',True),('latest','Последняя правка UTC',False)],data['types'])],charts)


def read_kendo():
    files=list(Path('/opt/kendo-recovery/site').rglob('*.html'));counts=Counter()
    for p in files:
        relative=str(p.relative_to('/opt/kendo-recovery/site'));group='news' if re.search(r'(^|/)news/',relative) else 'articles' if re.search(r'(^|/)articles/',relative) else 'other'
        counts[group]+=1
    kpis=[metric('news_publications','Новости в восстановленной копии',counts['news']-int((Path('/opt/kendo-recovery/site/news/index.html')).is_file()),'шт',source='news/*.html; исключён только news/index.html'),metric('articles_publications','Статьи в восстановленной копии',counts['articles']-int((Path('/opt/kendo-recovery/site/articles/index.html')).is_file()),'шт',source='articles/*.html; исключён только articles/index.html'),metric('pages','HTML страниц',len(files),'шт',source='RU3 static filesystem'),metric('news_files','HTML в разделе новостей, включая индекс',counts['news'],'шт',source='RU3 static filesystem'),metric('article_files','HTML в разделе статей, включая индекс',counts['articles'],'шт',source='RU3 static filesystem')]+unknown_finance('Статический клубный сайт: коммерческий регистр не подтверждён','не применимо',True)
    return document(kpis,[table('static_inventory','Файлы сайта: это не новые публикации',[('group','Раздел',False),('count','HTML файлов',True)],[dict(group=k,count=v) for k,v in counts.items()])])


def read_trade():
    from trade_sandbox_reader import read_trade as read_sandbox
    return read_sandbox(metric, table, document)
