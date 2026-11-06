"""Attach the verified closed October audit without claiming cash or profit."""
MISSING = 'Monthly native ledger/cost coverage unavailable; not zero'


def apply_october(doc, audit):
    if audit['period'] != '2026-10' or audit['category'] != 'accrued_income_valuation':
        raise ValueError('Unexpected Flux audit scope')
    stamp = audit['observed_at']
    source = 'October coinbase ledger + Fusion shares; CoinGecko 2026-10-31'
    hint = ('Оценка начислений до расходов, не денежные поступления и не прибыль. '
            'PA рассчитаны: 10 × 10% native; независимой месячной выписки PA нет. '
            'Точная оценка 6241,46 ₽; единый курс конца периода 4,870813363148789 RUB/FLUX.')
    metrics = []
    for id, label, value, unit, category in [
        ('october_accrued_valuation_rub', 'Начислено за октябрь 2026 · native + PA',
         audit['display_rub'], '₽', 'accrued_income_valuation'),
        ('october_native_flux', 'Native получено за октябрь 2026',
         float(audit['native_flux']), 'FLUX', 'native_receipts'),
        ('october_pa_accrued', 'PA начислено за октябрь 2026 · расчёт',
         float(audit['pa_flux_equivalent']), 'FLUX-экв.', 'accrual'),
    ]:
        metrics.append(dict(id=id, metric=id, label=label, value=value, unit=unit,
                            category=category, period='2026-10 · Asia/Vladivostok',
                            source=source, generated_at=stamp, last_success=stamp,
                            source_latest_at=audit['source_latest_at'],
                            status='historical', error=None, hint=hint))
    metrics[0]['exact_value'] = audit['valuation_rub']
    ids = {x['id'] for x in metrics}
    doc['kpis'] = metrics + [x for x in doc['kpis'] if x['id'] not in ids]
    for item in doc['kpis']:
        if item.get('error') == MISSING:
            item['error'] = ('Расходы и прибыль не подтверждены' if item['category'] in
                             ('expenses', 'profit') else 'Поступления или начисления за этот период не подтверждены')
    doc['error'] = (doc.get('error') or '').replace(MISSING, '').strip('; ') or None
    limits = [x for x in doc.get('limitations', []) if x.get('id') != 'monthly_finances']
    additions = [
        dict(id='flux_october_pa', title='Октябрьский native-реестр доступен; PA рассчитаны',
             impact='196 coinbase-выплат: 640,70 FLUX. PA +640,70 FLUX-экв. по долям Fusion; сроки claims неизвестны.',
             action='Для независимого подтверждения PA нужна месячная выписка.'),
        dict(id='flux_november_history', title='История ноября 2026 неполная',
             impact='November MTD не предоставлен. Октябрьская оценка не заполняет ноябрьские показатели.',
             action='Подключить проверенный реестр ноября.'),
        dict(id='flux_costs_profit', title='Расходы и прибыль неизвестны',
             impact='Расходы, комиссии и реализованные денежные поступления не сверены; прибыль не рассчитана.',
             action='Сверить расходы и денежные поступления за тот же период.'),
    ]
    known = {x['id'] for x in additions}
    doc['limitations'] = [x for x in limits if x.get('id') not in known] + additions
    table = dict(id='october_accrual_valuation', title='Октябрь 2026 · начисления и оценка до расходов',
                 columns=[dict(key='component', label='Показатель'), dict(key='value', label='Значение')],
                 rows=[dict(component=k, value=v) for k, v in [
                     ('Coinbase-выплат', audit['native_reward_count']),
                     ('Native, FLUX', audit['native_flux']),
                     ('PA расчётные, FLUX-экв.', audit['pa_flux_equivalent']),
                     ('Всего начислено, FLUX-экв.', audit['total_flux_equivalent']),
                     ('Курс 31.10.2026, RUB/FLUX', audit['rate_rub_per_flux']),
                     ('Точная оценка, RUB', audit['valuation_rub']),
                     ('Денежные поступления, RUB', None), ('Расходы, RUB', None), ('Прибыль, RUB', None)]],
                 period='2026-10 · Asia/Vladivostok', source=source, generated_at=stamp,
                 last_success=stamp, source_latest_at=audit['source_latest_at'], status='historical', error=None)
    doc['tables'] = [table] + [x for x in doc.get('tables', []) if x['id'] != table['id']]
    return doc
