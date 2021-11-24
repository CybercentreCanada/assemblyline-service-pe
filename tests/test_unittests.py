import pe.pe


class TestUnittests:
    @staticmethod
    def test_search_list_in_list():
        # At start
        what = [0, 1]
        into = [0, 1, 2, 3]
        res = pe.pe.search_list_in_list(what, into)
        assert res

        # In the middle
        what = [1, 2]
        into = [0, 1, 2, 3]
        res = pe.pe.search_list_in_list(what, into)
        assert res

        # At end
        what = [2, 3]
        into = [0, 1, 2, 3]
        res = pe.pe.search_list_in_list(what, into)
        assert res

        # Whole
        what = [0, 1, 2, 3]
        into = [0, 1, 2, 3]
        res = pe.pe.search_list_in_list(what, into)
        assert res

        # Not present
        what = [1, 3]
        into = [0, 1, 2, 3]
        res = pe.pe.search_list_in_list(what, into)
        assert not res

        # Bigger
        what = [0, 1, 2, 3, 3]
        into = [0, 1, 2, 3]
        res = pe.pe.search_list_in_list(what, into)
        assert not res
