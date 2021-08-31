import base64
import hashlib
import hmac
import json
import smtplib
from email.mime.text import MIMEText

import requests
from flask import Flask, request, abort

app = Flask(__name__)

# SECRET = b'82444557b6bfb5d80a78175fc159de99369aa809dea20387a5bd894c84af266b'  # ours


SECRET = b'268201170e1462874b91db36486cf737d8919be220dd2a237d7e83f862a69373'


def verify_webhook(data, hmac_header):
    digest = hmac.new(SECRET, data, hashlib.sha256).digest()
    computed_hmac = base64.b64encode(digest)
    return hmac.compare_digest(computed_hmac, str.encode(hmac_header))


@app.route('/webhook/order_create', methods=['POST'])
def handle_webhook():
    global p_title, p_sku, r_email
    r_email = 'orders.bocaonlinejudaica@gmail.com'
    # r_email = 'annonymousids@gmail.com'
    data = request.get_data()
    verified = verify_webhook(data, request.headers.get('X-Shopify-Hmac-SHA256'))

    if not verified:
        abort(401)
    else:
        data = str(data)
        fix_bytes_value = data.replace("b'", "")
        fix_bytes_value = fix_bytes_value.replace("'", "").replace("\\", "\\\\")
        my_json = json.loads(fix_bytes_value)
        shipping_address_detail = my_json['shipping_address']
        costumer_name = shipping_address_detail['first_name'] + " " + shipping_address_detail['last_name']
        shipping_address = shipping_address_detail['address1'] + " " + shipping_address_detail['city'] + " " + \
                           shipping_address_detail["zip"] + " " + shipping_address_detail['province'] + " " + \
                           shipping_address_detail["country"]
        order_num = my_json['order_number']
        print(order_num)
        line_items = my_json['line_items']
        product_ids = []
        variant_titles = []
        order_quantities = []
        vendors = []
        variant_ids = []
        product_titles = []
        skus = []
        print(list(shipping_address_detail))
        for i in line_items:
            product_ids.append(i['product_id'])
            product_titles.append(i['title'])
            skus.append(i['sku'])
            variant_titles.append(i['variant_title'])
            order_quantities.append(i['quantity'])
            variant_ids.append(i['variant_id'])
            vendors.append(i['vendor'])

        reserve_vendors = [{'name': 'A&M Judaica', 'website': ''},
                           {'name': 'Artscroll Mesorah', 'website': 'trade.artscoll.com'},
                           {'name': 'Artscroll', 'website': 'trade.artscoll.com'}]

        # vendor_dic = [
        #     {'name': 'Keter', 'email': 'hasnainkhan6099@gmail.com'},
        #     {'name': 'Feldheim', 'email': 'hasnain6099@gmail.com'},
        #     {'name': 'Isreali Bookshop', 'email': 'hasnainkhan6099@gmail.com'},
        #     {'name': 'Menucha Publishers', 'email': 'hasnainkhan6099@gmail.com'},
        #     {'name': 'Legacy', 'email': 'hasnainkhan6099@gmail.com'},
        #     {'name': 'Hachai Publishing', 'email': 'hasnainkhan6099@gmail.com'},
        # ]
        vendor_dic = [
            {'name': 'Keter', 'email': 'sales@keterjudaica.com'},
            {'name': 'Feldheim', 'email': 'suzanne@feldheim.com'},
            {'name': 'Isreali Bookshop', 'email': 'info@israelbookshoppublications.com'},
            {'name': 'Menucha Publishers', 'email': 'sales@menuchapublishers.com'},
            {'name': 'Legacy', 'email': 'asher@legacyjudaica.com'},
            {'name': 'Hachai Publishing', 'email': 'yossi@hachai.com'},
        ]

        for i, j, k, l in zip(product_ids, order_quantities, skus, product_titles):
            product_check = 'https://0074a54b86a439c0a986512eb107e9ea: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@boca' \
                            '-online-judaics.myshopify.com/admin/api/2021-07/products/{}.json'.format(i)
            result = requests.get(product_check)
            product_detail = result.json()
            print("product_detail", product_detail)
            variants = []
            vendor = []
            try:
                variants = product_detail['product']['variants']
            except (TypeError, KeyError):
                print("error in variant")
            try:
                vendor = product_detail['product']['vendor']
            except (TypeError, KeyError):
                print("error in vendor")
            ''' unknown vendor'''
            if len(vendor) == 0:
                order_numb = order_num
                p_title = l
                p_sku = k
                customer_name = costumer_name
                s_address = shipping_address
                unknown_vendor(r_email, p_title, p_sku, order_numb, "UNKNOWN", customer_name, s_address)
            for ji in variants:
                v_id = ji['id']
                if v_id in variant_ids:
                    inventory_quantity = ji['inventory_quantity']
                    if inventory_quantity <= -1 or inventory_quantity < j:
                        for ki in vendor_dic:
                            if ki['name'] == vendor:
                                v_email = ki['email']
                                quantity = j
                                customer_name = costumer_name
                                s_address = shipping_address
                                send_mail_quantity_l_zero(v_email, quantity, p_title, p_sku, customer_name, s_address)
                                break
                        for k1 in reserve_vendors:
                            if k1['name'] == vendor:
                                v_name = vendor
                                v_web = k1['website']
                                order_numb = order_num
                                # r_email = 'annonymousids@gmail.com'
                                p_title = l
                                p_sku = k
                                vendor_art_am(r_email, p_title, p_sku, order_numb, v_name, v_web)
                                break
                            print("Vendor", vendor)
                            if vendor == "Boca Online Judaica":
                                self_mail("orders.bocaonlinejudaica@gmail.com", order_num, p_title)
                    else:
                        order_numb = order_num
                        p_title = l
                        p_sku = k
                        customer_name = costumer_name
                        s_address = shipping_address
                        send_mail_quantity_g_zero(r_email, p_title, p_sku, order_numb, customer_name, s_address)
                else:
                    pass
    return 'Webhook verified', 200


def send_mail(r_email1, Mail_Content):
    server = smtplib.SMTP_SSL('smtp.gmail.com', 465)
    server.login("orders.bocaonlinejudaica@gmail.com", "Judaica123!")
    # server.login("annonymousids@gmail.com", "Galaxyj5")  # Judaica123!
    From = 'orders.bocaonlinejudaica@gmail.com'
    # From = 'annonymosids@gmail.com'
    To = r_email1
    message = MIMEText(Mail_Content)
    message['Subject'] = "New Order"
    message['From'] = From
    message['To'] = r_email1
    server.sendmail(From, To, message.as_string())
    server.quit()


def self_mail(r_email1, order_num, p_title1):
    Mail_Content = '''
            A Order was just created: order # {} and product: {} is supplied by Boca Online Judaica.
            '''.format(order_num, p_title1)
    send_mail(r_email1, Mail_Content)


def send_mail_quantity_g_zero(r_email1, p_title1, p_sku1, order_num, customer_name, s_address):
    Mail_Content = '''
            The following Product was just ordered and is in stock at the BOJ warehouse.
            {} 
            SKU number {} in 
            Order Number # {} is in stock 
            and needs to be shipped out to:
            {}
            Shipping Address : {}
            '''.format(p_title1, p_sku1, order_num, customer_name, s_address)
    send_mail(r_email1, Mail_Content)


def send_mail_quantity_l_zero(r_email2, quantity, p_title2, p_sku2, customer_name, s_address):
    Mail_Content = '''
                The following Product was just ordered and is in stock at the BOJ warehouse.

                Hi,Please send via usps or cheapest shipping method:
                Quanity: {} of : {} 
                item # {} 
                to: {} 
                Shipping address : {}
                Thank You!AviBoca Online Judaica'''.format(quantity, str(p_title2).capitalize(), p_sku2,
                                                           str(customer_name).capitalize(), s_address)
    send_mail(r_email2, Mail_Content)


def vendor_art_am(r_email3, p_title3, p_sku3, order_num, v_name, v_web):
    Mail_Content = '''
                    Hi, Title: {} SKU {} in order {} is 
                    wholesaled with {} and needs you to place the order through 
                   {}'''.format(str(p_title3).capitalize(), p_sku3, order_num, str(v_name).capitalize(), v_web)
    send_mail(r_email3, Mail_Content)


def unknown_vendor(r_email4, p_title4, p_sku4, order_num, v_name, customer_name, s_address):
    Mail_Content = '''
           {} SKU {} in order {} is wholesaled by {} 
           and needs your attention. 
           {} {}'''.format(str(p_title4).capitalize(), p_sku4, order_num, str(v_name).capitalize(),
                           str(customer_name).capitalize(), s_address)
    send_mail(r_email4, Mail_Content)


if __name__ == "__main__":
    app.run(debug=True, port=1234)
