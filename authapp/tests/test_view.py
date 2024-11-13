from .test_setup import TestSetUp


class TestViews(TestSetUp):

    def test_user_can_not_register_without_data(self):
        res = self.client.post(self.register_url)
        self.assertEqual(res.status_code, 400)

    def test_user_can_register_correctly(self):
        res = self.client.post(self.register_url, self.user_data, format="json")

        # Print the response data for debugging
        print("Response data:", res.data)

        # Continue with assertions if the response is as expected
        self.assertEqual(res.status_code, 201)

        if isinstance(
            res.data, dict
        ):  # If the response is a dictionary, check for keys
            self.assertEqual(res.data["email"], self.user_data["email"])
            self.assertEqual(res.data["username"], self.user_data["username"])
        else:
            print("Unexpected response format:", res.data)

    # def test_user_can_not_login_with_unverified_email(self):
    #     res = self.client.post(self.register_url, self.user_data, format="json")
    #     res = self.client.post(self.login_url, self.user_data, format="json")
    #     self.assertEqual(res.status_code, 400)
