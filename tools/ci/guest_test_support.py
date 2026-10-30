"""Bounded retries through the controller's normal save/close API only."""
import json
import time

def close_vm(vm):
    attempts = []
    for number in range(1, 4):
        try:
            vm.close()
            attempts.append({'attempt': number, 'closed': True})
            return True, attempts
        except RuntimeError as error:
            private = str(error)
            kind = 'other_runtime_failure'
            for prefix, label in (
                ('SD保存尚未完成', 'save_pending'),
                ('SD保存失败', 'save_failed'),
                ('SD保存/关闭未完成', 'save_or_close_incomplete'),
                ('VM清理', 'cleanup_failed'),
                ('VM尚未完成退出', 'exit_pending')):
                if private.startswith(prefix):
                    kind = label
                    break
            state = vm.status()
            record = {'attempt': number, 'closed': False, 'kind': kind,
                      'state': state['state'], 'export_ok': bool((state.get('sd_export') or {}).get('ok'))}
            attempts.append(record)
            print(json.dumps({'close_attempt': record}), flush=True)
            if number < 3:
                time.sleep(10)
    return False, attempts

def matches_yellow_mask(pixels, points, enabled):
    """Require the exact glyph mask; a solid rectangle or one missing pixel fails."""
    expected = set(points) if enabled else set()
    return all((pixels.getpixel((x,y)) == (255,255,0)) == ((x,y) in expected)
               for y in range(16,40) for x in range(16,176))
